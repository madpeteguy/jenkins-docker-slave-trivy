import sys
import os.path
import json
from pathlib import Path
from xml.dom.minidom import Document

__xml_document = Document()


def main(argv):
    json_path, xml_path = parse_args(argv)
    print(f"Load {json_path}")
    json_data = load_json(json_path)
    build_xml(json_data)
    print(f"Save {xml_path}")
    save_xml(xml_path)


def parse_args(argv):
    assert len(argv) >= 2, f"{len(argv)} Usage {os.path.basename(argv[0])} source.json [target.xml]"
    json_path = argv[1]
    if len(argv) >= 3:
        xml_path = argv[2]
    else:
        xml_path = json_path.rsplit(".", 1)[0] + ".xml"
    return json_path, xml_path


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def build_xml(json_data):
    # Reset the global document for each main call to build_xml
    global __xml_document
    __xml_document = Document()
    
    tss = xml_testsuites('Trivy') # This will now use the fresh __xml_document
    # Ensure 'Results' exists and is a list before iterating
    if 'Results' in json_data and isinstance(json_data['Results'], list):
        for json_result in json_data['Results']:
            if isinstance(json_result, dict): # Ensure each result is a dictionary
                 build_result(json_data, json_result, tss)


def build_result(json_data, json_result, tss):
    tests_count = 0
    failures_count = 0
    errors_count = 0
    skipped_count = 0

    # Use .get() for safer access, defaulting to empty list if key missing or None
    json_vulns = json_result.get('Vulnerabilities') or []
    json_secrets = json_result.get('Secrets') or []
    
    # Ensure json_vulns and json_secrets are lists before processing
    if isinstance(json_vulns, list):
        tests_count += len(json_vulns)
        for vuln in json_vulns:
            if not isinstance(vuln, dict): continue # Skip if vuln is not a dict
            severity_type = pick_type_by_severity(vuln.get('Severity', 'UNKNOWN'))
            if severity_type == 'failure':
                failures_count += 1
            elif severity_type == 'error':
                errors_count += 1
            elif severity_type == 'skipped':
                skipped_count += 1
    
    if isinstance(json_secrets, list):
        tests_count += len(json_secrets)
        for secret in json_secrets:
            if not isinstance(secret, dict): continue # Skip if secret is not a dict
            severity_type = pick_type_by_severity(secret.get('Severity', 'UNKNOWN'))
            if severity_type == 'failure':
                failures_count += 1
            elif severity_type == 'error':
                errors_count += 1
            elif severity_type == 'skipped':
                skipped_count += 1

    target_name = json_result.get('Target', 'UnknownTarget')
    # Use .get for CreatedAt from the main json_data, not per-result
    created_at_time = json_data.get('CreatedAt', '') 

    ts = xml_testsuite(tss, target_name, tests_count, failures_count, skipped_count, errors_count, created_at_time)
    
    prop_name_type = json_result.get('Type', '')
    prop_name_class = json_result.get('Class', '')
    prop_name = prop_name_type if prop_name_type else prop_name_class
    if not prop_name and tests_count > 0: # Add a default property only if there are items and no other type/class
        prop_name = 'DefaultTargetType'
    
    if prop_name:
      xml_properties(ts, prop_name)
    
    if isinstance(json_vulns, list):
        for json_vuln in json_vulns:
            if isinstance(json_vuln, dict): # Ensure item is a dict
                build_vuln(json_vuln, ts)
    if isinstance(json_secrets, list):
        for json_secret in json_secrets:
            if isinstance(json_secret, dict): # Ensure item is a dict
                build_secret(json_secret, ts)


def build_vuln(json_vuln, ts):
    severity = json_vuln.get('Severity', 'UNKNOWN')
    vulnerability_id = json_vuln.get('VulnerabilityID', 'N/A')
    pkg_name = json_vuln.get('PkgName', 'N/A')
    installed_version = str(json_vuln.get('InstalledVersion', 'N/A')) # Ensure string

    name = f"{vulnerability_id} [{severity}]"
    classname = f"{pkg_name}.{installed_version.replace('.', '_')}"
    
    tc = xml_testcase(ts, name, classname)
    title = json_vuln.get('Title', '') 
    description = json_vuln.get('Description', '') 
    build_testcase_content(tc, severity, title, description)


def build_secret(json_secret, ts):
    severity = json_secret.get('Severity', 'UNKNOWN')
    rule_id = json_secret.get('RuleID', 'N/A')
    category = json_secret.get('Category', 'N/A')

    name = f"{rule_id} [{severity}]"
    classname = f"Secrets.{category}"

    tc = xml_testcase(ts, name, classname)
    title = json_secret.get('Title', '')
    description = json_secret.get('Match', '')
    build_testcase_content(tc, severity, title, description)


def build_testcase_content(testcase, severity, title, description):
    severity_type = pick_type_by_severity(severity) # Severity already defaulted in callers
    
    title_str = str(title) if title is not None else ''
    description_str = str(description) if description is not None else ''

    if severity_type == 'error':
        xml_error(testcase, title_str, description_str)
    elif severity_type == 'failure':
        xml_failure(testcase, title_str, description_str)
    elif severity_type == 'skipped':
        xml_skipped(testcase, title_str)
        xml_systemerr(testcase, description_str)
    elif severity_type == 'passed':
        xml_systemout(testcase, title_str)
        xml_systemerr(testcase, description_str)
    else:
        # This case should ideally not be reached if pick_type_by_severity is robust
        # However, as a fallback, treat as error.
        xml_error(testcase, f"UnknownSeverityType: {severity_type}", f"Original Severity: {severity}\n{description_str}")


def pick_type_by_severity(severity):
    severity_str = str(severity).upper() # Ensure uppercase for comparison
    if severity_str == 'CRITICAL' or severity_str == 'HIGH':
        return 'failure'
    elif severity_str == 'MEDIUM':
        return 'skipped'
    elif severity_str == 'LOW':
        return 'passed'
    elif severity_str == 'UNKNOWN': 
        return 'error'
    else:
        # If a new severity appears that's not in the list, treat as error.
        # This is safer than raising an exception, allows report generation.
        # print(f"Warning: Unknown severity '{severity}' encountered. Treating as 'error'.", file=sys.stderr)
        return 'error' 


def xml_testsuites(name):
    # __xml_document is now reset in build_xml, which is the main entry point from main()
    # This ensures that if main() -> build_xml() is called, it gets a fresh doc.
    # If xml_testsuites were called from somewhere else independently, it might need its own reset.
    # For current script structure, build_xml() is the right place.
    testsuites = __xml_document.createElement("testsuites")
    testsuites.setAttribute('name', name)
    __xml_document.appendChild(testsuites)
    return testsuites


def xml_testsuite(testsuites, name, tests, failures, skipped, errors, time):
    testsuite = __xml_document.createElement("testsuite")
    testsuite.setAttribute('name', str(name))
    testsuite.setAttribute('tests', str(tests)) 
    testsuite.setAttribute('failures', str(failures)) 
    testsuite.setAttribute('errors', str(errors)) 
    testsuite.setAttribute('skipped', str(skipped)) 
    testsuite.setAttribute('time', str(time if time else '')) # Ensure time is not None
    testsuites.appendChild(testsuite)
    return testsuite


def xml_properties(testsuite, name):
    prop = __xml_document.createElement("property")
    prop.setAttribute('name', 'type')
    prop.setAttribute('value', str(name)) # Ensure value is string
    props = __xml_document.createElement("properties")
    else:
        name = json_result['Class']
    xml_properties(ts, name)
    if json_vulns is not None:
        for json_vuln in json_vulns:
            build_vuln(json_vuln, ts)
    if json_secrets is not None:
        for json_secret in json_secrets:
            build_secret(json_secret, ts)


def build_vuln(json_vuln, ts):
    # This part is already covered by the change block above.
    # The .get() methods and f-string formatting are applied.
    # title and description handling also covered.
    # build_testcase_content and pick_type_by_severity also covered.
    # xml_testsuites, xml_testsuite, xml_properties also covered.
    # The only remaining part is save_xml.
    props.appendChild(prop)
    testsuite.appendChild(props)
    return props


def xml_testcase(testsuite, name, classname):
    testcase = __xml_document.createElement("testcase")
    testcase.setAttribute('classname', classname)
    testcase.setAttribute('name', name)
    testcase.setAttribute('time', '')
    testsuite.appendChild(testcase)
    return testcase


def xml_skipped(testcase, message):
    skipped = __xml_document.createElement("skipped")
    skipped.setAttribute('message', message)
    testcase.appendChild(skipped)
    return skipped


def xml_error(testcase, message, description):
    error = __xml_document.createElement("error")
    error.setAttribute('message', message)
    error.setAttribute('type', 'description')
    error.appendChild(__xml_document.createTextNode(description))
    testcase.appendChild(error)
    return error


def xml_failure(testcase, message, description):
    failure = __xml_document.createElement("failure")
    failure.setAttribute('message', message)
    failure.setAttribute('type', 'description')
    failure.appendChild(__xml_document.createTextNode(description))
    testcase.appendChild(failure)
    return failure


def xml_systemout(testcase, message):
    systemout = __xml_document.createElement("system-out")
    systemout.appendChild(__xml_document.createTextNode(message))
    testcase.appendChild(systemout)
    return systemout


def xml_systemerr(testcase, message):
    systemerr = __xml_document.createElement("system-err")
    systemerr.appendChild(__xml_document.createTextNode(message))
    testcase.appendChild(systemerr)
    return systemerr


def save_xml(xml_path):
    # Ensure output directory exists
    output_dir = Path(xml_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(xml_path, "w", encoding="utf-8") as xml_file:
        # Ensure __xml_document is the one we've been working with.
        # If build_xml was called, it would have reset and used the global.
        __xml_document.writexml(xml_file, encoding="utf-8", newl="\n", addindent='    ')


if __name__ == '__main__':
    main(sys.argv)
