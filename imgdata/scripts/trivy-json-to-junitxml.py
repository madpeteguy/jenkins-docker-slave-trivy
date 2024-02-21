import sys
import os.path
import json
from pathlib import Path
from xml.dom.minidom import Document

__xml_document = Document()


def load_json(path):
    f = open(path, "r", encoding="utf-8")
    data = json.load(f)
    f.close()
    return data


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


def xml_failure(testcase, message, description):
    failure = __xml_document.createElement("failure")
    failure.setAttribute('message', message)
    failure.setAttribute('type', 'description')
    failure.appendChild(__xml_document.createTextNode(description))
    testcase.appendChild(failure)
    return failure


def main(argv):
    assert len(argv) >= 2, f"{len(argv)} Usage {os.path.basename(argv[0])} source.json [target.xml]"
    json_path = argv[1]
    if len(argv) >= 3:
        xml_path = argv[2]
    else:
        xml_path = json_path.rsplit(".", 1)[0] + ".xml"
    print(f"Load {json_path}")
    json_data = load_json(json_path)
    tss = xml_testsuites('Trivy')
    for json_result in json_data['Results']:
        json_vulns = json_result['Vulnerabilities']
        ts = xml_testsuite(tss, json_result['Target'], str(len(json_vulns)), str(len(json_vulns)),
                           json_data['CreatedAt'])
        xml_properties(ts, json_result['Type'])
        for json_vuln in json_vulns:
            name = "[{0}] {1}".format(json_vuln['Severity'], json_vuln['VulnerabilityID'])
            classname = "{0}-{1}".format(json_vuln['PkgName'], json_vuln['InstalledVersion'])
            tc = xml_testcase(ts, name, classname)
            title = ''
            if 'Title' in json_vuln:
                title = json_vuln['Title']
            xml_failure(tc, title, json_vuln['Description'])
    print(f"Save {xml_path}")
    (Path.cwd() / os.path.dirname(xml_path)).mkdir(parents=True, exist_ok=True)
    xml_file = open(xml_path, "w", encoding="utf-8")
    __xml_document.writexml(xml_file, encoding="utf-8", newl="\n", addindent='    ')
    xml_file.close()


if __name__ == '__main__':
    main(sys.argv)
