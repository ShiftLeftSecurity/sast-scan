import lib.convert as convertLib


import json
import tempfile


def test_nodejsscan_convert_empty():
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", delete=True
    ) as cfile:
        data = convertLib.report("nodejsscan", [], {}, {}, [], cfile.name)
        jsondata = json.loads(data)
        assert jsondata["runs"][0]["tool"]["driver"]["name"] == "nodejsscan"
        assert not jsondata["runs"][0]["results"]
        assert not jsondata["runs"][0]["properties"]["metrics"]


def test_nodejsscan_convert_issue():
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", delete=True
    ) as cfile:
        data = convertLib.report(
            "nodejsscan",
            [],
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
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", delete=True
    ) as cfile:
        data = convertLib.report(
            "nodejsscan",
            [],
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
