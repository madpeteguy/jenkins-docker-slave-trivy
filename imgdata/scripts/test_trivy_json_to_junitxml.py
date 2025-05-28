import unittest
import json
import xml.etree.ElementTree as ET
import os
import sys
from pathlib import Path

# Add the script's directory to sys.path to allow importing trivy_json_to_junitxml
SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

import trivy_json_to_junitxml # pyright: ignore[reportMissingImports]

class TestTrivyJsonToJunitXml(unittest.TestCase):

    def _run_script_with_json(self, json_data):
        """Helper to run the script's main logic with in-memory JSON data."""
        # Create temporary files for input and output
        temp_json_file = Path("temp_test_input.json")
        temp_xml_file = Path("temp_test_output.xml")

        try:
            with open(temp_json_file, 'w') as f:
                json.dump(json_data, f)
            
            # Modify __xml_document global in the script module before each run
            # to ensure a fresh Document object for each test.
            trivy_json_to_junitxml.__xml_document = trivy_json_to_junitxml.Document()

            trivy_json_to_junitxml.main([sys.argv[0], str(temp_json_file), str(temp_xml_file)])
            
            with open(temp_xml_file, 'r') as f:
                xml_output = f.read()
            
            return ET.fromstring(xml_output)
        finally:
            # Clean up temporary files
            if temp_json_file.exists():
                os.remove(temp_json_file)
            if temp_xml_file.exists():
                os.remove(temp_xml_file)

    def test_single_critical_vulnerability(self):
        json_input = {
            "CreatedAt": "2023-01-01T00:00:00Z",
            "Results": [
                {
                    "Target": "myimage:latest",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0001",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1k-r0",
                            "Severity": "CRITICAL",
                            "Title": "Critical OpenSSL vuln"
                        }
                    ]
                }
            ]
        }
        root = self._run_script_with_json(json_input)
        self.assertEqual(len(root.findall("testsuite")), 1)
        testsuite = root.find("testsuite")
        self.assertEqual(testsuite.get("name"), "myimage:latest")
        self.assertEqual(testsuite.get("tests"), "1")
        self.assertEqual(testsuite.get("failures"), "1")
        self.assertEqual(testsuite.get("errors"), "0")
        self.assertEqual(testsuite.get("skipped"), "0")
        testcases = testsuite.findall("testcase")
        self.assertEqual(len(testcases), 1)
        self.assertIsNotNone(testcases[0].find("failure"))

    def test_high_secret_medium_vulnerability(self):
        json_input = {
            "CreatedAt": "2023-01-01T00:00:00Z",
            "Results": [
                {
                    "Target": "app/pom.xml",
                    "Class": "lang-pkgs",
                    "Type": "maven",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0002",
                            "PkgName": "log4j",
                            "InstalledVersion": "2.14.0",
                            "Severity": "MEDIUM",
                            "Title": "Medium Log4j vuln"
                        }
                    ],
                    "Secrets": [
                        {
                            "RuleID": "AWS_KEY",
                            "Category": "AWS",
                            "Severity": "HIGH",
                            "Title": "AWS Access Key"
                        }
                    ]
                }
            ]
        }
        root = self._run_script_with_json(json_input)
        self.assertEqual(len(root.findall("testsuite")), 1)
        testsuite = root.find("testsuite")
        self.assertEqual(testsuite.get("name"), "app/pom.xml")
        self.assertEqual(testsuite.get("tests"), "2")
        self.assertEqual(testsuite.get("failures"), "1") # HIGH secret
        self.assertEqual(testsuite.get("errors"), "0")
        self.assertEqual(testsuite.get("skipped"), "1") # MEDIUM vuln
        testcases = testsuite.findall("testcase")
        self.assertEqual(len(testcases), 2)
        
        # Check for one failure and one skipped
        failure_found = False
        skipped_found = False
        for tc in testcases:
            if tc.find("failure") is not None:
                failure_found = True
            if tc.find("skipped") is not None:
                skipped_found = True
        self.assertTrue(failure_found)
        self.assertTrue(skipped_found)

    def test_low_vulnerability_unknown_secret(self):
        json_input = {
            "CreatedAt": "2023-01-01T00:00:00Z",
            "Results": [
                {
                    "Target": "config.yaml",
                    "Class": "config",
                    "Type": "yaml",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0003",
                            "PkgName": "internal-lib",
                            "InstalledVersion": "1.0.0",
                            "Severity": "LOW",
                            "Title": "Low severity issue"
                        }
                    ],
                    "Secrets": [
                        {
                            "RuleID": "GENERIC_API_KEY",
                            "Category": "Generic",
                            "Severity": "UNKNOWN",
                            "Title": "Unknown severity secret"
                        }
                    ]
                }
            ]
        }
        root = self._run_script_with_json(json_input)
        testsuite = root.find("testsuite")
        self.assertEqual(testsuite.get("tests"), "2")
        self.assertEqual(testsuite.get("failures"), "0")
        self.assertEqual(testsuite.get("errors"), "1") # UNKNOWN secret
        self.assertEqual(testsuite.get("skipped"), "0") 
        
        testcases = testsuite.findall("testcase")
        self.assertEqual(len(testcases), 2)
        
        error_found = False
        passed_found = False # Low is treated as passed
        for tc in testcases:
            if tc.find("error") is not None:
                error_found = True
            # A "passed" testcase has no failure, error, or skipped child
            if tc.find("failure") is None and tc.find("error") is None and tc.find("skipped") is None:
                passed_found = True
        self.assertTrue(error_found)
        self.assertTrue(passed_found)

    def test_no_vulnerabilities_or_secrets(self):
        json_input = {
            "CreatedAt": "2023-01-01T00:00:00Z",
            "Results": [
                {
                    "Target": "cleanimage:latest",
                    "Class": "os-pkgs",
                    "Type": "debian",
                    "Vulnerabilities": None, # Explicitly None
                    "Secrets": [] # Empty list
                }
            ]
        }
        root = self._run_script_with_json(json_input)
        testsuite = root.find("testsuite")
        self.assertEqual(testsuite.get("tests"), "0")
        self.assertEqual(testsuite.get("failures"), "0")
        self.assertEqual(testsuite.get("errors"), "0")
        self.assertEqual(testsuite.get("skipped"), "0")
        self.assertEqual(len(testsuite.findall("testcase")), 0)

    def test_multiple_targets(self):
        json_input = {
            "CreatedAt": "2023-01-01T00:00:00Z",
            "Results": [
                {
                    "Target": "image1:tag",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-HIGH", "PkgName": "lib1", "InstalledVersion": "1.0", "Severity": "HIGH"}
                    ]
                },
                {
                    "Target": "image2:tag",
                     "Secrets": [
                        {"RuleID": "SEC-MED", "Category": "Generic", "Severity": "MEDIUM"}
                    ]
                }
            ]
        }
        root = self._run_script_with_json(json_input)
        testsuites = root.findall("testsuite")
        self.assertEqual(len(testsuites), 2)

        ts1 = next(ts for ts in testsuites if ts.get("name") == "image1:tag")
        self.assertEqual(ts1.get("tests"), "1")
        self.assertEqual(ts1.get("failures"), "1")
        self.assertEqual(ts1.get("errors"), "0")
        self.assertEqual(ts1.get("skipped"), "0")
        self.assertEqual(len(ts1.findall("testcase")), 1)
        self.assertIsNotNone(ts1.find("testcase/failure"))

        ts2 = next(ts for ts in testsuites if ts.get("name") == "image2:tag")
        self.assertEqual(ts2.get("tests"), "1")
        self.assertEqual(ts2.get("failures"), "0")
        self.assertEqual(ts2.get("errors"), "0")
        self.assertEqual(ts2.get("skipped"), "1")
        self.assertEqual(len(ts2.findall("testcase")), 1)
        self.assertIsNotNone(ts2.find("testcase/skipped"))

    def test_missing_fields_graceful_handling(self):
        # Test that the script doesn't crash with missing optional fields
        # and uses defaults (Severity -> UNKNOWN -> error)
        json_input = {
            "CreatedAt": "2023-01-01T00:00:00Z", # CreatedAt might be missing in some Trivy versions/outputs for individual results
            "Results": [
                {
                    "Target": "image_with_missing_fields",
                    # "Class": "os-pkgs", # Missing Class
                    # "Type": "alpine",   # Missing Type
                    "Vulnerabilities": [
                        {
                            # "VulnerabilityID": "CVE-MISSING", # Missing ID
                            "PkgName": "lib-unknown",
                            "InstalledVersion": "1.0",
                            # "Severity": "HIGH", # Missing Severity
                            # "Title": "A vuln" # Missing Title
                        }
                    ]
                }
            ]
        }
        root = self._run_script_with_json(json_input)
        testsuite = root.find("testsuite")
        self.assertIsNotNone(testsuite)
        self.assertEqual(testsuite.get("name"), "image_with_missing_fields")
        self.assertEqual(testsuite.get("tests"), "1")
        self.assertEqual(testsuite.get("failures"), "0") # Missing severity defaults to UNKNOWN -> error
        self.assertEqual(testsuite.get("errors"), "1")
        self.assertEqual(testsuite.get("skipped"), "0")
        
        testcase = testsuite.find("testcase")
        self.assertIsNotNone(testcase)
        self.assertTrue(testcase.get("name").startswith("N/A")) # Default for VulnID
        self.assertTrue("[UNKNOWN]" in testcase.get("name")) # Default for Severity
        self.assertIsNotNone(testcase.find("error"))

    def test_null_vulnerabilities_secrets(self):
        # Handles cases where "Vulnerabilities" or "Secrets" is explicitly null
        json_input = {
            "CreatedAt": "2023-01-01T00:00:00Z",
            "Results": [
                {
                    "Target": "image-nulls",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": None,
                    "Secrets": None
                }
            ]
        }
        root = self._run_script_with_json(json_input)
        testsuite = root.find("testsuite")
        self.assertEqual(testsuite.get("name"), "image-nulls")
        self.assertEqual(testsuite.get("tests"), "0")
        self.assertEqual(testsuite.get("failures"), "0")
        self.assertEqual(testsuite.get("errors"), "0")
        self.assertEqual(testsuite.get("skipped"), "0")
        self.assertEqual(len(testsuite.findall("testcase")), 0)


if __name__ == '__main__':
    unittest.main()
