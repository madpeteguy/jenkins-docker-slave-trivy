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
    name = "[{0}] {1}".format(severity, json_vuln['VulnerabilityID'])
    classname = "{0}-{1}".format(json_vuln['PkgName'], json_vuln['InstalledVersion'])
    tc = xml_testcase(ts, name, classname)
    title = 'Title' in json_vuln and json_vuln['Title'] or ''
    description = 'Description' in json_vuln and json_vuln['Description'] or ''
    if severity == 'LOW':
        xml_result(tc, title, description, "skipped")
    elif severity == 'UNKNOWN':
        xml_result(tc, title, description, "error")
    else:
        xml_result(tc, title, description)


def build_secret(json_secret, ts):
    name = "[{0}] {1}".format(json_secret['Severity'], json_secret['RuleID'])
    classname = json_secret['Category']
    tc = xml_testcase(ts, name, classname)
    title = 'Title' in json_secret and json_secret['Title'] or ''
    description = 'Match' in json_secret and json_secret['Match'] or ''
    xml_result(tc, title, description)


def xml_testsuites(name):
    testsuites = __xml_document.createElement("testsuites")
    testsuites.setAttribute('name', name)
    __xml_document.appendChild(testsuites)
    return testsuites


def xml_testsuite(testsuites, name, tests=None, failures=None, time=None):
    testsuite = __xml_document.createElement("testsuite")
    testsuite.setAttribute('tests', tests)
    testsuite.setAttribute('failures', failures)
    testsuite.setAttribute('name', name)
    testsuite.setAttribute('errors', '0')
    testsuite.setAttribute('skipped', '0')
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


def xml_result(testcase, message, description, result_tag="failure"):
    result = __xml_document.createElement(result_tag)
    result.setAttribute('message', message)
    result.setAttribute('type', 'description')
    result.appendChild(__xml_document.createTextNode(description))
    testcase.appendChild(result)
    systemout = __xml_document.createElement("system-out")
    systemout.appendChild(__xml_document.createTextNode(description))
    testcase.appendChild(systemout)
    systemerr = __xml_document.createElement("system-err")
    systemerr.appendChild(__xml_document.createTextNode(message))
    testcase.appendChild(systemerr)
    return result


def save_xml(xml_path):
    (Path.cwd() / os.path.dirname(xml_path)).mkdir(parents=True, exist_ok=True)
    xml_file = open(xml_path, "w", encoding="utf-8")
    __xml_document.writexml(xml_file, encoding="utf-8", newl="\n", addindent='    ')
    xml_file.close()


if __name__ == '__main__':
    main(sys.argv)
