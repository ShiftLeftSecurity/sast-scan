import importlib
import json
import os
import tempfile
import uuid
from pathlib import Path

import lib.convert as convertLib
import lib.issue as issueLib


def test_nodejsscan_convert_empty():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report("nodejsscan", [], ".", {}, {}, [], cfile.name)
        jsondata = json.loads(data)
        assert (
            jsondata["runs"][0]["automationDetails"]["description"]["text"]
            == "Static Analysis Security Test results using @ShiftLeft/sast-scan"
        )
        assert uuid.UUID(jsondata["inlineExternalProperties"][0]["guid"]).version == 4
        assert not jsondata["runs"][0]["results"]
        assert jsondata["runs"][0]["properties"]["metrics"] == {
            "total": 0,
            "critical": 0,
            "high": 0,
            "low": 0,
            "medium": 0,
        }


def test_nodejsscan_convert_issue():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "nodejsscan",
            [],
            ".",
            {},
            {},
            [
                {
                    "description": "MD5 is a a weak hash which is known to have collision. Use a strong hashing function.",
                    "filename": "InsufficientPasswordHash.js",
                    "line": 3,
                    "lines": 'function hashPassword(password) {\n    var crypto = require("crypto");\n    var hasher = crypto.createHash(\'md5\');\n    var hashed = hasher.update(password).digest("hex"); // BAD\n    return hashed;\n}',
                    "path": "/github/workspace/CWE-916/examples/InsufficientPasswordHash.js",
                    "sha2": "bfc3a2dfec54a8e77e41c3e3d7a6d87477ea1ed6d1cb3b1b60b8e135b0d18368",
                    "tag": "node",
                    "title": "Weak Hash used - MD5",
                }
            ],
            cfile.name,
        )
        jsondata = json.loads(data)
        assert (
            jsondata["runs"][0]["results"][0]["message"]["text"]
            == "MD5 is a a weak hash which is known to have collision. Use a strong hashing function."
        )


def test_nodejsscan_convert_metrics():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "nodejsscan",
            [],
            ".",
            {
                "total_count": {"good": 0, "mis": 8, "sec": 4},
                "vuln_count": {
                    "Loading of untrusted YAML can cause Remote Code Injection": 1,
                    "Weak Hash used - MD5": 1,
                    "XSS - Reflected Cross Site Scripting": 2,
                },
            },
            {},
            [],
            cfile.name,
        )
        jsondata = json.loads(data)
        assert jsondata["runs"][0]["properties"]["metrics"]


def test_create_result():
    issue = issueLib.issue_from_dict(
        {
            "description": "MD5 is a a weak hash which is known to have collision. Use a strong hashing function.",
            "filename": "InsufficientPasswordHash.js",
            "line": 3,
            "lines": 'function hashPassword(password) {\n    var crypto = require("crypto");\n    var hasher = crypto.createHash(\'md5\');\n    var hashed = hasher.update(password).digest("hex"); // BAD\n    return hashed;\n}',
            "path": "/app/src/CWE-916/examples/InsufficientPasswordHash.js",
            "sha2": "bfc3a2dfec54a8e77e41c3e3d7a6d87477ea1ed6d1cb3b1b60b8e135b0d18368",
            "tag": "node",
            "title": "Weak Hash used - MD5",
        }
    )
    data = convertLib.create_result("nodetest", issue, {}, {}, None, "/app/src")
    assert (
        data.locations[0].physical_location.artifact_location.uri
        == "file:///app/src/CWE-916/examples/InsufficientPasswordHash.js"
    )
    # Override the workspace and check the location
    os.environ["WORKSPACE"] = "/foo/bar"
    importlib.reload(convertLib)
    data = convertLib.create_result("nodetest", issue, {}, {}, None, "/app/src")
    assert (
        data.locations[0].physical_location.artifact_location.uri
        == "file:///foo/bar/CWE-916/examples/InsufficientPasswordHash.js"
    )
    # Override the workspace and check the location
    os.environ["WORKSPACE"] = "https://github.com/ShiftLeftSecurity/cdxgen/blob/master"
    importlib.reload(convertLib)
    data = convertLib.create_result("nodetest", issue, {}, {}, None, "/app/src")
    assert (
        data.locations[0].physical_location.artifact_location.uri
        == "https://github.com/ShiftLeftSecurity/cdxgen/blob/master/CWE-916/examples/InsufficientPasswordHash.js"
    )


def test_create_result_relative():
    os.environ["WORKSPACE"] = ""
    importlib.reload(convertLib)
    issue = issueLib.issue_from_dict(
        {
            "line": "VERY_REDACTED ",
            "offender": "REDACTED",
            "commit": "06fd7b1f844f88fb7821df498ce6d209cb9ad875",
            "repo": "app",
            "rule": "Generic Credential",
            "commitMessage": "Add secret\n",
            "author": "Team ShiftLeft",
            "email": "hello@shiftleft.io",
            "file": "src/main/README-new.md",
            "date": "2020-01-12T19:45:43Z",
            "tags": "key, API, generic",
        }
    )
    data = convertLib.create_result("gitleaks", issue, {}, {}, None, "/app")
    assert (
        data.locations[0].physical_location.artifact_location.uri
        == "src/main/README-new.md"
    )


def test_credscan_convert_issue():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "credscan",
            [],
            ".",
            {},
            {},
            [
                {
                    "line": "VERY_SECRET_TOO = 'f6CGV4aMM9zedoh3OUNbSakBymo7yplB' ",
                    "offender": "SECRET_TOO = 'f6CGV4aMM9zedoh3OUNbSakBymo7yplB'",
                    "commit": "f5cf9d795d00ac5540f3ba26a1d98d9bc9c4bbbc",
                    "repo": "app",
                    "rule": "Generic Credential",
                    "commitMessage": "password\n",
                    "author": "guest Subramanian",
                    "email": "guest@ngcloud.io",
                    "file": "README.md",
                    "date": "2020-01-02T21:02:40Z",
                    "tags": "key, API, generic",
                }
            ],
            cfile.name,
        )
        jsondata = json.loads(data)
        assert jsondata["runs"][0]["results"][0]["message"]["text"]
        assert jsondata["runs"][0]["properties"]["metrics"] == {
            "high": 1,
            "total": 1,
            "critical": 0,
            "medium": 0,
            "low": 0,
        }


def test_credscan_convert_unc():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "credscan",
            [],
            ".",
            {},
            {},
            [
                {
                    "line": "\naws_access_key_id='AKIAIO5FODNN7EXAMPLE'",
                    "offender": "AKIAIO5FODNN7EXAMPLE",
                    "commit": "0000000000000000000000000000000000000000",
                    "repo": "app",
                    "rule": "AWS Manager ID",
                    "commitMessage": "***STAGED CHANGES***",
                    "author": "",
                    "email": "",
                    "file": "/Users/guest/work/ShiftLeft/HelloShiftLeft/README.md",
                    "date": "1970-01-01T00:00:00Z",
                    "tags": "key, AWS",
                }
            ],
            cfile.name,
        )
        jsondata = json.loads(data)
        assert jsondata["runs"][0]["results"][0]["message"]["text"]
        assert jsondata["runs"][0]["properties"]["metrics"] == {
            "high": 1,
            "total": 1,
            "critical": 0,
            "medium": 0,
            "low": 0,
        }


def test_gosec_convert_issue():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "gosec",
            [],
            ".",
            {},
            {},
            [
                {
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "rule_id": "G104",
                    "details": "Errors unhandled.",
                    "file": "/app/lib/plugins/capture/capture.go",
                    "code": "io.Copy(reqbody, cwc.r.Request.Body)",
                    "line": "57",
                }
            ],
            cfile.name,
        )
        jsondata = json.loads(data)
        assert jsondata["runs"][0]["results"][0]["message"]["text"]
        assert jsondata["runs"][0]["properties"]["metrics"] == {
            "medium": 1,
            "total": 1,
            "critical": 0,
            "high": 0,
            "low": 0,
        }


def test_tfsec_convert_issue():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "lint-tf",
            [],
            ".",
            {},
            {},
            [
                {
                    "rule_id": "AWSTEST",
                    "link": "https://github.com/aquasecurity/tfsec/wiki/AWS018",
                    "location": {
                        "filename": "/app/main.tf",
                        "start_line": 1,
                        "end_line": 4,
                    },
                    "description": "Resource 'aws_security_group_rule.my-rule' should include a description for auditing purposes.",
                    "severity": "ERROR",
                }
            ],
            cfile.name,
        )
        jsondata = json.loads(data)
        assert (
            jsondata["runs"][0]["results"][0]["message"]["text"]
            == "Resource 'aws_security_group_rule.my-rule' should include a description for auditing purposes."
        )
        assert jsondata["runs"][0]["properties"]["metrics"] == {
            "critical": 1,
            "total": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
        }


def test_checkov_convert_issue():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "checkov",
            [],
            ".",
            {},
            {},
            [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
                    "check_result": {"result": "FAILED"},
                    "code_block": [
                        [1, 'resource "aws_s3_bucket" "data" {\n'],
                        [2, "  # bucket is public\n"],
                        [3, "  # bucket is not encrypted\n"],
                        [4, "  # bucket does not have access logs\n"],
                        [5, "  # bucket does not have versioning\n"],
                        [
                            6,
                            '  bucket        = "${local.resource_prefix.value}-data"\n',
                        ],
                        [7, '  acl           = "public-read"\n'],
                        [8, "  force_destroy = true\n"],
                        [9, "  tags = {\n"],
                        [
                            10,
                            '    Name        = "${local.resource_prefix.value}-data"\n',
                        ],
                        [11, "    Environment = local.resource_prefix.value\n"],
                        [12, "  }\n"],
                        [13, "}\n"],
                    ],
                    "file_path": "/terraform/s3.tf",
                    "file_line_range": [1, 13],
                    "resource": "aws_s3_bucket.data",
                    "evaluations": "",
                    "check_class": "checkov.terraform.checks.resource.aws.S3PublicACLRead",
                },
                {
                    "check_id": "CKV_AWS_52",
                    "check_name": "Ensure S3 bucket has MFA delete enabled",
                    "check_result": {"result": "FAILED"},
                    "code_block": [
                        [171, 'resource "aws_s3_bucket" "flowbucket" {\n'],
                        [172, '  bucket = "${local.resource_prefix.value}-flowlogs"\n'],
                        [173, "  force_destroy = true\n"],
                        [174, "\n"],
                        [175, "  tags = {\n"],
                        [
                            176,
                            '    Name        = "${local.resource_prefix.value}-flowlogs"\n',
                        ],
                        [177, "    Environment = local.resource_prefix.value\n"],
                        [178, "  }\n"],
                        [179, "}\n"],
                    ],
                    "file_path": "/terraform/ec2.tf",
                    "file_line_range": [171, 179],
                    "resource": "aws_s3_bucket.flowbucket",
                    "evaluations": {},
                    "check_class": "checkov.terraform.checks.resource.aws.S3MFADelete",
                },
            ],
            cfile.name,
        )
        jsondata = json.loads(data)
        assert (
            jsondata["runs"][0]["results"][0]["message"]["text"]
            == "S3 Bucket has an ACL defined which allows public READ access."
        )
        assert jsondata["runs"][0]["properties"]["metrics"] == {
            "critical": 1,
            "total": 2,
            "high": 0,
            "medium": 0,
            "low": 1,
        }


def test_staticcheck_convert_issue():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "staticcheck",
            [],
            ".",
            {},
            {},
            [
                {
                    "code": "ST1005",
                    "severity": "error",
                    "location": {
                        "file": "/Users/guest/go/kube-score/cmd/kube-score/main.go",
                        "line": 156,
                        "column": 10,
                    },
                    "end": {
                        "file": "/Users/guest/go/kube-score/cmd/kube-score/main.go",
                        "line": 156,
                        "column": 86,
                    },
                    "message": "error strings should not be capitalized",
                }
            ],
            cfile.name,
        )
        jsondata = json.loads(data)
        assert (
            jsondata["runs"][0]["results"][0]["message"]["text"]
            == "error strings should not be capitalized."
        )
        assert jsondata["runs"][0]["properties"]["metrics"] == {
            "critical": 0,
            "total": 1,
            "high": 0,
            "medium": 0,
            "low": 1,
        }


def test_to_uri():
    p = convertLib.to_uri("https://github.com/shiftleft/sast-scan")
    assert p == "https://github.com/shiftleft/sast-scan"
    p = convertLib.to_uri("README.md")
    assert p == "README.md"
    p = convertLib.to_uri("/home/guest/work/README.md")
    assert p == "file:///home/guest/work/README.md"
    p = convertLib.to_uri("c:\\users\\guest\\work\\README.md")
    assert p == "file:///c:/users/guest/work/README.md"
    p = convertLib.to_uri("c:\\users\\guest\\work/com/src/main/README.md")
    assert p == "file:///c:/users/guest/work/com/src/main/README.md"


def test_inspect_convert_issue():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "ng-sast",
            [],
            ".",
            {},
            {},
            [
                {
                    "applicationId": "HelloShiftLeft",
                    "vulnerability": {
                        "firstDetected": "1587134045",
                        "vulnerabilityId": "command-injection-attacker-controlled/b9790fedb5c49bf0c10a7cf72b0a5eab",
                        "category": "a1-injection",
                        "title": "Remote Code Execution: Command Injection through attacker-controlled data via `foo` in `SearchController.doGetSearch`",
                        "description": "Attacker controlled data is used in a shell command without undergoing escaping or validation. This could allow an attacker to execute code on the server. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. By injecting hostile data, an attacker may trick the interpreter into executing unintended commands or accessing data without authorization which can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, denial of access or even a complete host takeover.\n\n\n## Countermeasures\n\nThis vulnerability can be prevented by using parameterized queries or by validating HTTP data (preferably on server-side by means of common input sanitation libraries or whitelisting) before using it.\n\n## Additional information\n\n**[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**\n\n**[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**\n\n**[CWE-917](https://cwe.mitre.org/data/definitions/917.html)**\n\n**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**",
                        "score": 9,
                        "severity": "SEVERITY_HIGH_IMPACT",
                        "dataFlow": {
                            "spId": "sl/49089d37-68ff-47e3-9035-269e6e91a44d/HelloShiftLeft/86ad7190555ddb774563ac58d242919db87a0265/56f81248989870704c18042cc58d9ff18573e7aff5f1a8cb2a92f022556a20be/1",
                            "occurrenceHash": "b9790fedb5c49bf0c10a7cf72b0a5eab",
                            "dataFlow": {
                                "list": [
                                    {
                                        "location": {
                                            "lineNumber": 21,
                                            "packageName": "io.shiftleft.controller",
                                            "className": "io.shiftleft.controller.SearchController",
                                            "methodName": "io.shiftleft.controller.SearchController.doGetSearch:java.lang.String(java.lang.String,javax.servlet.http.HttpServletResponse,javax.servlet.http.HttpServletRequest)",
                                            "shortMethodName": "doGetSearch",
                                            "fileName": "io/shiftleft/controller/SearchController.java",
                                        },
                                        "variableInfo": {
                                            "parameter": {
                                                "symbol": "foo",
                                                "paramIndex": 1,
                                                "type": "java.lang.String",
                                            }
                                        },
                                        "methodId": "6974698689270346897",
                                        "parameterId": "6974698689270346900",
                                        "methodTags": [
                                            {"key": "INTERFACE_WRITE"},
                                            {"key": "EXPOSED_METHOD"},
                                            {"key": "INTERFACE_READ"},
                                            {
                                                "key": "EXPOSED_METHOD_ROUTE",
                                                "value": "/search/user",
                                            },
                                        ],
                                        "parameterTags": [
                                            {"key": "FROM_OUTSIDE", "value": "http"},
                                            {
                                                "key": "DATA_TYPE",
                                                "value": "attacker-controlled",
                                            },
                                        ],
                                        "id": "6974698689270346900",
                                    },
                                    {
                                        "location": {
                                            "lineNumber": 25,
                                            "packageName": "io.shiftleft.controller",
                                            "className": "io.shiftleft.controller.SearchController",
                                            "methodName": "io.shiftleft.controller.SearchController.doGetSearch:java.lang.String(java.lang.String,javax.servlet.http.HttpServletResponse,javax.servlet.http.HttpServletRequest)",
                                            "shortMethodName": "doGetSearch",
                                            "fileName": "io/shiftleft/controller/SearchController.java",
                                        },
                                        "variableInfo": {
                                            "local": {
                                                "symbol": "foo",
                                                "type": "java.lang.String",
                                            }
                                        },
                                        "methodId": "6974698689270346897",
                                        "methodTags": [
                                            {"key": "INTERFACE_WRITE"},
                                            {"key": "EXPOSED_METHOD"},
                                            {"key": "INTERFACE_READ"},
                                            {
                                                "key": "EXPOSED_METHOD_ROUTE",
                                                "value": "/search/user",
                                            },
                                        ],
                                        "id": "6974698689270346957",
                                    },
                                    {
                                        "location": {
                                            "packageName": "org.springframework.expression.spel.standard",
                                            "className": "org.springframework.expression.spel.standard.SpelExpressionParser",
                                            "methodName": "org.springframework.expression.spel.standard.SpelExpressionParser.parseExpression:org.springframework.expression.Expression(java.lang.String)",
                                            "shortMethodName": "parseExpression",
                                            "fileName": "org/springframework/expression/spel/standard/SpelExpressionParser.java",
                                        },
                                        "variableInfo": {
                                            "parameter": {
                                                "symbol": "param0",
                                                "paramIndex": 1,
                                                "type": "java.lang.String",
                                            }
                                        },
                                        "methodId": "2545",
                                        "parameterId": "2548",
                                        "methodTags": [
                                            {"key": "INTERFACE_READ"},
                                            {"key": "INTERFACE_WRITE"},
                                        ],
                                        "parameterTags": [
                                            {"key": "TO_OUTSIDE", "value": "execute"},
                                            {
                                                "key": "DESCRIPTOR_USE",
                                                "value": "execute",
                                            },
                                        ],
                                        "id": "2548",
                                    },
                                ]
                            },
                        },
                        "firstVersionDetected": "86ad7190555ddb774563ac58d242919db87a0265",
                    },
                }
            ],
            cfile.name,
        )
        jsondata = json.loads(data)
        assert jsondata


def test_inspect_extract_issue():
    issues, metrics, skips = convertLib.extract_from_file(
        "ng-sast",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "inspect-report.json",
    )
    assert issues
    assert len(issues) == 174
    assert issues[0] == {
        "rule_id": "a1-injection",
        "title": "Remote Code Execution: Command Injection through attacker-controlled data via `foo` in `SearchController.doGetSearch`",
        "description": "Attacker controlled data is used in a shell command without undergoing escaping or validation. This could allow an attacker to execute code on the server. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. By injecting hostile data, an attacker may trick the interpreter into executing unintended commands or accessing data without authorization which can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, denial of access or even a complete host takeover.\n\n\n## Countermeasures\n\nThis vulnerability can be prevented by using parameterized queries or by validating HTTP data (preferably on server-side by means of common input sanitation libraries or whitelisting) before using it.\n\n## Additional information\n\n**[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**\n\n**[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**\n\n**[CWE-917](https://cwe.mitre.org/data/definitions/917.html)**\n\n**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**",
        "score": 9,
        "severity": "SEVERITY_HIGH_IMPACT",
        "line_number": 21,
        "filename": "io/shiftleft/controller/SearchController.java",
        "first_found": "86ad7190555ddb774563ac58d242919db87a0265",
        "issue_confidence": "HIGH",
    }


def test_inspect_extract_issue_nodejs():
    issues, metrics, skips = convertLib.extract_from_file(
        "ng-sast",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "inspect-nodejs.json",
    )
    assert issues
    assert len(issues) == 9
    assert issues[0] == {
        "rule_id": "a1-injection",
        "title": "Remote Code Execution: Command Injection through HTTP via `req` in `:=>`",
        "description": "HTTP data is used in a shell command without undergoing escaping or validation. This could allow an attacker to execute code on the server. Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. By injecting hostile data, an attacker may trick the interpreter into executing unintended commands or accessing data without authorization which can result in data loss, corruption, or disclosure to unauthorized parties, loss of accountability, denial of access or even a complete host takeover.\n\n\n## Countermeasures\n\nThis vulnerability can be prevented by using parameterized queries or by validating HTTP data (preferably on server-side by means of common input sanitation libraries or whitelisting) before using it.\n\n## Additional information\n\n**[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**\n\n**[CWE-78](https://cwe.mitre.org/data/definitions/78.html)**\n\n**[CWE-917](https://cwe.mitre.org/data/definitions/917.html)**\n\n**[OWASP-A1](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)**",
        "score": 9,
        "severity": "SEVERITY_HIGH_IMPACT",
        "line_number": 11,
        "filename": "src/views.js",
        "first_found": "e1ca1d72ed01311eee71a6f0110b789263815a5c5ac442dd7db65f985f57e7e3",
        "issue_confidence": "HIGH",
    }


def test_njsscan_extract_issue():
    issues, metrics, skips = convertLib.extract_from_file(
        "source-js",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "njsscan-report.json",
    )
    assert issues
    assert len(issues) == 7
    assert issues[0] == {
        "rule_id": "a1-injection",
        "title": "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
        "description": "Untrusted user input in redirect() can result in Open Redirect vulnerability.",
        "severity": "ERROR",
        "line_number": 72,
        "filename": "/Users/prabhu/work/NodeGoat/app/routes/index.js",
        "issue_confidence": "HIGH",
    }
    issues, metrics, skips = convertLib.extract_from_file(
        "source-js",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "njs2.json",
    )
    assert issues
    assert len(issues) == 26
    assert issues[0] == {
        "rule_id": "a9-usingcomponentswithknownvulnerabilities",
        "title": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        "description": "crypto.pseudoRandomBytes()/Math.random() is a cryptographically weak random number generator.",
        "severity": "WARNING",
        "line_number": 7,
        "filename": "vendor/ckeditor/ckeditor/vendor/promise.js",
        "issue_confidence": "HIGH",
    }
    assert issues[-1] == {
        "rule_id": "a1-injection",
        "title": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "description": "The Vue.js template has an unescaped variable. Untrusted user input passed to this variable results in Cross Site Scripting (XSS).",
        "severity": "ERROR",
        "line_number": 0,
        "filename": "src/layouts/basic/modules/Chat/components/ChatPanelRight.vue",
        "issue_confidence": "HIGH",
    }


def test_convert_dataflow():
    dataflows = convertLib.convert_dataflow(
        "/app",
        [],
        [
            {
                "location": {
                    "lineNumber": 11,
                    "methodName": "src/views.js::program::=>::=>2",
                    "shortMethodName": ":=>",
                    "fileName": "src/views.js",
                },
                "variableInfo": {
                    "parameter": {"symbol": "req", "paramIndex": 1, "type": "ANY"}
                },
                "methodId": "2162",
                "parameterId": "2165",
                "methodTags": [
                    {"key": "EXPOSED_METHOD"},
                    {"key": "EXPOSED_METHOD_ROUTE", "value": '"/user-input"'},
                ],
                "parameterTags": [
                    {"key": "FROM_OUTSIDE", "value": "http"},
                    {"key": "FROM_OUTSIDE", "value": "attacker-controlled"},
                ],
                "id": "2165",
            }
        ],
    )
    assert len(dataflows) == 1
    assert dataflows == [{"filename": "src/views.js", "line_number": 11}]

    dataflows = convertLib.convert_dataflow(
        "/app",
        [],
        [
            {
                "location": {
                    "lineNumber": 11,
                    "methodName": "src/views.js::program::=>::=>2",
                    "shortMethodName": ":=>",
                    "fileName": "src/views.js",
                },
                "variableInfo": {
                    "parameter": {"symbol": "req", "paramIndex": 1, "type": "ANY"}
                },
                "methodId": "2162",
                "parameterId": "2165",
                "methodTags": [
                    {"key": "EXPOSED_METHOD"},
                    {"key": "EXPOSED_METHOD_ROUTE", "value": '"/user-input"'},
                ],
                "parameterTags": [
                    {"key": "FROM_OUTSIDE", "value": "http"},
                    {"key": "FROM_OUTSIDE", "value": "attacker-controlled"},
                ],
                "id": "2165",
            },
            {
                "location": {
                    "lineNumber": 19,
                    "methodName": "src/views.js::program::=>::=>2",
                    "shortMethodName": ":=>",
                    "fileName": "src/views.js",
                },
                "variableInfo": {"stack": {"type": "ANY"}},
                "methodId": "2162",
                "methodTags": [
                    {"key": "EXPOSED_METHOD"},
                    {"key": "EXPOSED_METHOD_ROUTE", "value": '"/user-input"'},
                ],
                "id": "2190",
            },
            {
                "location": {
                    "methodName": "eval",
                    "shortMethodName": "eval",
                    "fileName": "N/A",
                },
                "variableInfo": {
                    "parameter": {"symbol": "p1", "paramIndex": 1, "type": "ANY"}
                },
                "methodId": "6522",
                "parameterId": "6523",
                "methodTags": [{"key": "INTERFACE_WRITE"}],
                "parameterTags": [{"key": "TO_OUTSIDE", "value": "execute"}],
                "id": "6523",
            },
        ],
    )
    assert len(dataflows) == 2
    assert dataflows == [
        {"filename": "src/views.js", "line_number": 11},
        {"filename": "src/views.js", "line_number": 19},
    ]

    dataflows = convertLib.convert_dataflow(
        "/app",
        [],
        [
            {
                "location": {
                    "lineNumber": 21,
                    "packageName": "io.shiftleft.controller",
                    "className": "io.shiftleft.controller.SearchController",
                    "methodName": "io.shiftleft.controller.SearchController.doGetSearch:java.lang.String(java.lang.String,javax.servlet.http.HttpServletResponse,javax.servlet.http.HttpServletRequest)",
                    "shortMethodName": "doGetSearch",
                    "fileName": "io/shiftleft/controller/SearchController.java",
                },
                "variableInfo": {
                    "parameter": {
                        "symbol": "foo",
                        "paramIndex": 1,
                        "type": "java.lang.String",
                    }
                },
                "methodId": "6974698689270346897",
                "parameterId": "6974698689270346900",
                "methodTags": [
                    {"key": "INTERFACE_WRITE"},
                    {"key": "EXPOSED_METHOD"},
                    {"key": "INTERFACE_READ"},
                    {"key": "EXPOSED_METHOD_ROUTE", "value": "/search/user"},
                ],
                "parameterTags": [
                    {"key": "FROM_OUTSIDE", "value": "http"},
                    {"key": "DATA_TYPE", "value": "attacker-controlled"},
                ],
                "id": "6974698689270346900",
            },
            {
                "location": {
                    "lineNumber": 25,
                    "packageName": "io.shiftleft.controller",
                    "className": "io.shiftleft.controller.SearchController",
                    "methodName": "io.shiftleft.controller.SearchController.doGetSearch:java.lang.String(java.lang.String,javax.servlet.http.HttpServletResponse,javax.servlet.http.HttpServletRequest)",
                    "shortMethodName": "doGetSearch",
                    "fileName": "io/shiftleft/controller/SearchController.java",
                },
                "variableInfo": {
                    "local": {"symbol": "foo", "type": "java.lang.String"}
                },
                "methodId": "6974698689270346897",
                "methodTags": [
                    {"key": "INTERFACE_WRITE"},
                    {"key": "EXPOSED_METHOD"},
                    {"key": "INTERFACE_READ"},
                    {"key": "EXPOSED_METHOD_ROUTE", "value": "/search/user"},
                ],
                "id": "6974698689270346957",
            },
            {
                "location": {
                    "packageName": "org.springframework.expression.spel.standard",
                    "className": "org.springframework.expression.spel.standard.SpelExpressionParser",
                    "methodName": "org.springframework.expression.spel.standard.SpelExpressionParser.parseExpression:org.springframework.expression.Expression(java.lang.String)",
                    "shortMethodName": "parseExpression",
                    "fileName": "org/springframework/expression/spel/standard/SpelExpressionParser.java",
                },
                "variableInfo": {
                    "parameter": {
                        "symbol": "param0",
                        "paramIndex": 1,
                        "type": "java.lang.String",
                    }
                },
                "methodId": "2545",
                "parameterId": "2548",
                "methodTags": [{"key": "INTERFACE_READ"}, {"key": "INTERFACE_WRITE"}],
                "parameterTags": [
                    {"key": "TO_OUTSIDE", "value": "execute"},
                    {"key": "DESCRIPTOR_USE", "value": "execute"},
                ],
                "id": "2548",
            },
        ],
    )
    assert len(dataflows) == 2


def test_psalm_extract_issue():
    issues, metrics, skips = convertLib.extract_from_file(
        "audit-php",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "audit-php.json",
    )
    assert issues
    assert len(issues) == 317
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "psalm",
            [],
            ".",
            {},
            {},
            issues,
            cfile.name,
        )
        jsondata = json.loads(data)
        assert (
            jsondata["runs"][0]["results"][0]["message"]["text"]
            == "Too many arguments for method PhpParser \\ NodeVisitor::enternode - saw 2."
        )
        assert jsondata["runs"][0]["properties"]["metrics"] == {
            "critical": 0,
            "total": 7,
            "high": 0,
            "medium": 7,
            "low": 0,
        }


def test_phpstan_extract_issue():
    issues, metrics, skips = convertLib.extract_from_file(
        "phpstan",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "source-php-report.json",
    )
    assert issues
    assert len(issues) == 670
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "phpstan",
            [],
            ".",
            {},
            {},
            issues,
            cfile.name,
        )
        jsondata = json.loads(data)
        assert (
            jsondata["runs"][0]["results"][0]["message"]["text"]
            == "Unsafe usage of new static()."
        )
        assert jsondata["runs"][0]["properties"]["metrics"] == {
            "critical": 0,
            "total": 470,
            "high": 0,
            "medium": 0,
            "low": 470,
        }


def test_get_help():
    url = convertLib.get_url(
        "source-java",
        "Error Prone",
        "Check if there is an error prone vulnerability",
        {},
    )
    assert url == "https://slscan.io?q=Error+Prone"
    url = convertLib.get_url(
        "source-js",
        "CWE-118 Incorrect Access of Indexable Resource ('Range Error') (4.0)",
        "Check if there is an incorrect access vulnerability",
        {},
    )
    assert (
        url
        == "https://cwe.mitre.org/data/definitions/118+Incorrect+Access+of+Indexable+Resource+%28%27Range+Error%27%29+%284.0%29.html"
    )


def test_phptaint_extract_issue():
    issues, metrics, skips = convertLib.extract_from_file(
        "taint-php",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "taint-php-report.json",
    )
    assert issues
    assert len(issues) == 7
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "taint-php",
            [],
            ".",
            {},
            {},
            issues,
            cfile.name,
        )
        jsondata = json.loads(data)
        assert (
            jsondata["runs"][0]["results"][0]["message"]["text"]
            == "Detected tainted shell in path: $_GET -> $_GET['username'] (CommandExecution/CommandExec-1.php:25:23) -> call to shell_exec (CommandExecution/CommandExec-1.php:25:23) -> shell_exec#1: ."
        )
        assert jsondata["runs"][0]["properties"]["metrics"] == {
            "critical": 7,
            "total": 7,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

    issues, metrics, skips = convertLib.extract_from_file(
        "taint-php",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "taint-php-report2.json",
    )
    assert issues
    assert len(issues) == 130
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "taint-php",
            [],
            ".",
            {},
            {},
            issues,
            cfile.name,
        )
        jsondata = json.loads(data)
        assert jsondata["runs"][0]["properties"]["metrics"] == {
            "critical": 130,
            "total": 130,
            "high": 0,
            "medium": 0,
            "low": 0,
        }


def test_static_suppress_issue():
    issues, metrics, skips = convertLib.extract_from_file(
        "staticcheck",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "staticcheck-ignore-report.json",
    )
    assert issues
    assert len(issues) == 76
    filtered_issues, suppress_list = convertLib.suppress_issues(issues)
    assert suppress_list


def test_go_suppress_issue():
    issues, metrics, skips = convertLib.extract_from_file(
        "source-go",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "source-go-ignore.json",
    )
    assert issues
    assert len(issues) == 5
    filtered_issues, suppress_list = convertLib.suppress_issues(issues)
    assert suppress_list
    assert len(suppress_list) == len(issues)
    assert not filtered_issues


def test_pytaint_extract_issue():
    issues, metrics, skips = convertLib.extract_from_file(
        "taint-python",
        [],
        Path(__file__).parent,
        Path(__file__).parent / "data" / "taint-python-report.json",
    )
    assert issues
    assert len(issues) == 27
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "taint-python",
            [],
            ".",
            {},
            {},
            issues,
            cfile.name,
        )
        jsondata = json.loads(data)
        assert (
            jsondata["runs"][0]["results"][0]["message"]["text"]
            == "Cross-site scripting (XSS) vulnerability with data reaching from the source `views.py:21` to the sink `views.py:24`."
        )
        assert jsondata["runs"][0]["properties"]["metrics"] == {
            "critical": 6,
            "total": 27,
            "high": 21,
            "medium": 0,
            "low": 0,
        }
        assert jsondata["runs"][0]["results"][0]["partialFingerprints"] == {
            "scanFileHash": "422e70bb97927cc5",
            "scanTagsHash": "d9a496fd1c3ce8a9",
        }


def test_ruby_convert_issue():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "source-ruby",
            [],
            ".",
            {},
            {},
            [
                {
                    "warning_type": "Remote Code Execution",
                    "warning_code": 25,
                    "fingerprint": "07f5143982fb589796b35ec8252bef03d1696639ba57242317926977ae7e0d49",
                    "check_name": "Deserialize",
                    "message": "`Marshal.load` called with parameter value",
                    "file": "app/controllers/password_resets_controller.rb",
                    "line": 6,
                    "link": "https://brakemanscanner.org/docs/warning_types/unsafe_deserialization",
                    "code": "Marshal.load(Base64.decode64(params[:user]))",
                    "render_path": "",
                    "location": {
                        "type": "method",
                        "class": "PasswordResetsController",
                        "method": "reset_password",
                    },
                    "user_input": "params[:user]",
                    "confidence": "Medium",
                },
                {
                    "warning_type": "SQL Injection",
                    "warning_code": 0,
                    "fingerprint": "27033d08c8870bed7adc52075447f220c78d5e3b2c42ad05dc2c36625a0f5774",
                    "check_name": "SQL",
                    "message": "Possible SQL injection",
                    "file": "app/models/analytics.rb",
                    "line": 3,
                    "link": "https://brakemanscanner.org/docs/warning_types/sql_injection/",
                    "code": 'select("#{col}")',
                    "render_path": "",
                    "location": {
                        "type": "method",
                        "class": "Analytics",
                        "method": "hits_by_ip",
                    },
                    "user_input": "col",
                    "confidence": "Medium",
                },
            ],
            cfile.name,
        )
        jsondata = json.loads(data)
        assert (
            jsondata["runs"][0]["results"][0]["message"]["text"]
            == "`Marshal.load` called with parameter value."
        )
        assert jsondata["runs"][0]["results"][0]["partialFingerprints"] == {
            "scanFileHash": "c7b25d276c64a838"
        }
