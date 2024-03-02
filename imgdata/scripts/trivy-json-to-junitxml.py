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
    f = open(path, "r", encoding="utf-8")
    data = json.load(f)
    f.close()
    return data


def build_xml(json_data):
    tss = xml_testsuites('Trivy')
    if 'Results' in json_data:
        for json_result in json_data['Results']:
            build_result(json_data, json_result, tss)


def build_result(json_data, json_result, tss):
    v_count = 0
    json_vulns = None
    json_secrets = None
    if 'Vulnerabilities' in json_result:
        json_vulns = json_result['Vulnerabilities']
        v_count += len(json_vulns)
    if 'Secrets' in json_result:
        json_secrets = json_result['Secrets']
        v_count += len(json_secrets)
    name = json_result['Target']
    time = json_data['CreatedAt']
    ts = xml_testsuite(tss, name, str(v_count), str(v_count), time)
    name = ''
    if 'Type' in json_result:
        name = json_result['Type']
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
    severity = json_vuln['Severity']
    name = "{0} [{1}]".format(json_vuln['VulnerabilityID'], severity)
    classname = "{0}.{1}".format(json_vuln['PkgName'], json_vuln['InstalledVersion'].replace('.', '_'))
    tc = xml_testcase(ts, name, classname)
    title = 'Title' in json_vuln and json_vuln['Title'] or ''
    description = 'Description' in json_vuln and json_vuln['Description'] or ''
    build_testcase_content(tc, severity, description, title)


def build_secret(json_secret, ts):
    severity = json_secret['Severity']
    name = "{0} [{1}]".format(json_secret['RuleID'], json_secret['Severity'])
    classname = "Secrets.{0}".format(json_secret['Category'])
    tc = xml_testcase(ts, name, classname)
    title = 'Title' in json_secret and json_secret['Title'] or ''
    description = 'Match' in json_secret and json_secret['Match'] or ''
    build_testcase_content(tc, severity, title, description)


def build_testcase_content(testcase, severity, title, description):
    severity_type = pick_type_by_severity(severity)
    if severity_type == 'error':
        xml_error(testcase, title, description)
    elif severity_type == 'failure':
        xml_failure(testcase, title, description)
    elif severity_type == 'skipped':
        xml_skipped(testcase, title)
        xml_systemerr(testcase, description)
    elif severity_type == 'passed':
        xml_systemout(testcase, title)
        xml_systemerr(testcase, description)
    else:
        raise RuntimeError(f"Unknown severity type \"{severity_type}\"")


def pick_type_by_severity(severity):
    if severity == 'CRITICAL' or severity == 'HIGH':
        return 'failure'
    elif severity == 'MEDIUM':
        return 'skipped'
    elif severity == 'LOW':
        return 'passed'
    elif severity == 'UNKNOWN':
        return 'error'
    else:
        raise RuntimeError(f"Unknown severity {severity}")


def xml_testsuites(name):
    testsuites = __xml_document.createElement("testsuites")
    testsuites.setAttribute('name', name)
    __xml_document.appendChild(testsuites)
    return testsuites


def xml_testsuite(testsuites, name, tests=None, failures=None, skipped=None, errors=None, time=None):
    testsuite = __xml_document.createElement("testsuite")
    testsuite.setAttribute('name', name)
    testsuite.setAttribute('tests', tests)
    testsuite.setAttribute('failures', failures)
    testsuite.setAttribute('errors', errors)
    testsuite.setAttribute('skipped', skipped)
    testsuite.setAttribute('time', '')
    testsuites.appendChild(testsuite)
    return testsuite


def xml_properties(testsuite, name):
    prop = __xml_document.createElement("property")
    prop.setAttribute('name', 'type')
    prop.setAttribute('value', name)
    props = __xml_document.createElement("properties")
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
    skipped = __xml_document.createElement("failure")
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
    (Path.cwd() / os.path.dirname(xml_path)).mkdir(parents=True, exist_ok=True)
    xml_file = open(xml_path, "w", encoding="utf-8")
    __xml_document.writexml(xml_file, encoding="utf-8", newl="\n", addindent='    ')
    xml_file.close()


if __name__ == '__main__':
    main(sys.argv)
