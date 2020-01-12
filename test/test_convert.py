import lib.convert as convertLib
import lib.issue as issueLib


import importlib
import json
import os
import tempfile


def test_nodejsscan_convert_empty():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report("nodejsscan", [], ".", {}, {}, [], cfile.name)
        jsondata = json.loads(data)
        assert jsondata["runs"][0]["tool"]["driver"]["name"] == "nodejsscan"
        assert not jsondata["runs"][0]["results"]
        assert not jsondata["runs"][0]["properties"]["metrics"]


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
        assert jsondata["runs"][0]["tool"]["driver"]["name"] == "nodejsscan"
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
        assert jsondata["runs"][0]["tool"]["driver"]["name"] == "nodejsscan"
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
    os.environ["WORKSPACE"] = "https://github.com/appthreat/cdxgen/blob/master"
    importlib.reload(convertLib)
    data = convertLib.create_result("nodetest", issue, {}, {}, None, "/app/src")
    assert (
        data.locations[0].physical_location.artifact_location.uri
        == "https://github.com/appthreat/cdxgen/blob/master/CWE-916/examples/InsufficientPasswordHash.js"
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
                    "author": "Prabhu Subramanian",
                    "email": "prabhu@ngcloud.io",
                    "file": "README.md",
                    "date": "2020-01-02T21:02:40Z",
                    "tags": "key, API, generic",
                }
            ],
            cfile.name,
        )
        jsondata = json.loads(data)
        assert jsondata["runs"][0]["tool"]["driver"]["name"] == "credscan"
        assert jsondata["runs"][0]["results"][0]["message"]["text"]


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
        assert jsondata["runs"][0]["tool"]["driver"]["name"] == "gosec"
        assert jsondata["runs"][0]["results"][0]["message"]["text"]


def test_tfsec_convert_issue():
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as cfile:
        data = convertLib.report(
            "tfsec",
            [],
            ".",
            {},
            {},
            [
                {
                    "rule_id": "AWS018",
                    "link": "https://github.com/liamg/tfsec/wiki/AWS018",
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
        assert jsondata["runs"][0]["tool"]["driver"]["name"] == "tfsec"
        assert (
            jsondata["runs"][0]["results"][0]["message"]["text"]
            == "Resource 'aws_security_group_rule.my-rule' should include a description for auditing purposes."
        )
