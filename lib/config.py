# This file is part of Scan.

# Scan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Scan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Scan.  If not, see <https://www.gnu.org/licenses/>.

import json
import logging
import os
import sys


LOG = logging.getLogger(__name__)

runtimeValues = {}

# Depth of credscan
credscan_depth = "2"
credscan_config = "/usr/local/src/credscan-config.toml"
DEPSCAN_CMD = "/usr/local/bin/depscan"

# Flag to disable telemetry
DISABLE_TELEMETRY = False

# Telemetry server
TELEMETRY_URL = "https://telemetry.appthreat.io/track"

# Line number hash size
HASH_DIGEST_SIZE = 8

# ShiftLeft Inspect CLI command
SHIFTLEFT_INSPECT_CMD = "/opt/sl-cli/sl-latest"

# ShiftLeft URI
SHIFTLEFT_URI = "https://www.shiftleft.io"

# ShiftLeft vulnerabilities api url
SHIFTLEFT_VULN_API = "{}/api/v3/public/org/%(sl_org)s/app/%(app_name)s/version/%(version)s/vulnerabilities".format(
    SHIFTLEFT_URI
)

"""
Supported language scan types. Unused as a variable
"""
scan_types = [
    "ansible",
    "apex",
    "aws",
    "bash",
    "bom",
    "credscan",
    "depscan",
    "go",
    "java",
    "jsp",
    "kotlin",
    "kubernetes",
    "nodejs",
    "plsql",
    "puppet",
    "python",
    "ruby",
    "rust",
    "terraform",
    "vf",
    "vm",
    "yaml",
]


# Default ignore list
ignore_directories = [
    ".git",
    ".svn",
    ".mvn",
    ".idea",
    "dist",
    "bin",
    "obj",
    "backup",
    "docs",
    "tests",
    "test",
    "tmp",
    "reports",
    "node_modules",
]


def get(configName, default_value=None):
    """Method to retrieve a config given a name. This method lazy loads configuration
    values and helps with overriding using a local config

    :param configName: Name of the config
    :return Config value
    """
    try:
        value = runtimeValues.get(configName)
        if value is None:
            value = os.environ.get(configName.upper())
        if value is None:
            value = getattr(sys.modules[__name__], configName, None)
        if value is None:
            value = default_value
        return value
    except Exception:
        return default_value


def set(configName, value):
    """Method to set a config during runtime

    :param configName: Config name
    :param value: Value
    """
    runtimeValues[configName] = value


"""
Mapping for application types to scan tools for projects requiring just a single tool
"""
scan_tools_args_map = {
    "ansible": [
        "ansible-lint",
        *["--exclude " + d for d in ignore_directories],
        "--parseable-severity",
        "*.yml",
    ],
    "apex": {
        "source": [
            *os.environ["PMD_CMD"].split(" "),
            "-no-cache",
            "--failOnViolation",
            "false",
            "-language",
            "apex",
            "-d",
            "%(src)s",
            "-r",
            "%(report_fname_prefix)s.csv",
            "-f",
            "csv",
            "-R",
            os.environ["APP_SRC_DIR"] + "/rules-pmd.xml",
        ]
    },
    "aws": ["cfn-lint", "-f", "json", "-e", "%(src)s/**/*.yaml"],
    "bom": ["cdxgen", "-o", "%(report_fname_prefix)s.xml", "%(src)s"],
    "credscan": [
        "gitleaks",
        "--config=" + get("credscan_config"),
        "--depth=" + get("credscan_depth"),
        "--repo-path=%(src)s",
        "--redact",
        "--timeout=2m",
        "--report=%(report_fname_prefix)s.json",
        "--report-format=json",
    ],
    "credscan-ide": [
        "gitleaks",
        "--config=" + get("credscan_config"),
        "--uncommitted",
        "--repo-path=%(src)s",
        "--timeout=2m",
        "--report=%(report_fname_prefix)s.json",
        "--report-format=json",
    ],
    "bash": [
        "shellcheck",
        "-a",
        "--shell=%(type)s",
        "-f",
        "json",
        "-S",
        "error",
        "--color=never",
        "(filelist=sh)",
    ],
    "depscan": [
        get("DEPSCAN_CMD"),
        "--no-banner",
        "--src",
        "%(src)s",
        "--report_file",
        "%(report_fname_prefix)s.json",
    ],
    "go": {
        "gosec": [
            "gosec",
            "-fmt=json",
            "-confidence=medium",
            "-severity=medium",
            "-no-fail",
            "-out=%(report_fname_prefix)s.json",
            "./...",
        ],
        "staticcheck": ["staticcheck", "-f", "json", "./..."],
    },
    "jsp": {
        "source": [
            *os.environ["PMD_CMD"].split(" "),
            "-no-cache",
            "--failOnViolation",
            "false",
            "-language",
            "jsp",
            "-d",
            "%(src)s",
            "-r",
            "%(report_fname_prefix)s.csv",
            "-f",
            "csv",
            "-R",
            os.environ["APP_SRC_DIR"] + "/rules-pmd.xml",
        ]
    },
    "kotlin": [
        "java",
        "-jar",
        "/usr/local/bin/detekt-cli.jar",
        "-i",
        "%(src)s",
        "-r",
        "xml:%(report_fname_prefix)s.xml",
    ],
    "kubernetes": ["kube-score", "score", "-o", "json", "(filelist=yaml)"],
    "plsql": {
        "source": [
            *os.environ["PMD_CMD"].split(" "),
            "-no-cache",
            "--failOnViolation",
            "false",
            "-language",
            "plsql",
            "-d",
            "%(src)s",
            "-r",
            "%(report_fname_prefix)s.csv",
            "-f",
            "csv",
            "-R",
            os.environ["APP_SRC_DIR"] + "/rules-pmd.xml",
        ]
    },
    "puppet": ["puppet-lint", "--error-level", "all", "--json", "%(src)s"],
    "rust": ["cargo-audit", "audit", "-q", "--json", "-c", "never"],
    "terraform": ["tfsec", "--format", "json", "--no-colour", "%(src)s"],
    "vf": {
        "source": [
            *os.environ["PMD_CMD"].split(" "),
            "-no-cache",
            "--failOnViolation",
            "false",
            "-language",
            "vf",
            "-d",
            "%(src)s",
            "-r",
            "%(report_fname_prefix)s.csv",
            "-f",
            "csv",
            "-R",
            os.environ["APP_SRC_DIR"] + "/rules-pmd.xml",
        ]
    },
    "vm": {
        "source": [
            *os.environ["PMD_CMD"].split(" "),
            "-no-cache",
            "--failOnViolation",
            "false",
            "-language",
            "vm",
            "-d",
            "%(src)s",
            "-r",
            "%(report_fname_prefix)s.csv",
            "-f",
            "csv",
            "-R",
            os.environ["APP_SRC_DIR"] + "/rules-pmd.xml",
        ]
    },
    "yaml": ["yamllint", "-f", "parsable", "(filelist=yaml)"],
}


"""
This map contains the SARIF purpose string for various tools
"""
tool_purpose_message = {
    "nodejsscan": "Static security code scan",
    "findsecbugs": "Class file analyzer",
    "pmd": "Source code analyzer",
    "/opt/pmd-bin/bin/run.sh": "Source code analyzer",
    "gitleaks": "Secrets audit",
    "gosec": "Security audit for Go",
    "tfsec": "Terraform static analysis",
    "shellcheck": "Shell script analysis",
    "bandit": "Security audit for python",
    "staticcheck": "Go static analysis",
    "source": "Source code analyzer",
    "binary": "Binary byte-code analyzer",
    "class": "Class file analyzer",
    "jar": "Jar file analyzer",
    "cpg": "ShiftLeft graph analyzer",
    "inspect": "ShiftLeft Inspect deep analyzer",
}

# Map to link to the reference for the given rule
tool_ref_url = {
    "shellcheck": "https://github.com/koalaman/shellcheck/wiki/SC%(rule_id)s",
    "gosec": "https://github.com/securego/gosec#available-rules",
    "staticcheck": "https://staticcheck.io/docs/checks#%(rule_id)s",
}

# Build break rules
build_break_rules = {"default": {"max_critical": 0, "max_high": 2, "max_medium": 5}}

# URL for viewing reports online
hosted_viewer_uri = "https://sarifviewer.azurewebsites.net"


def reload():
    # Load any .sastscanrc file from the root
    if get("SAST_SCAN_SRC_DIR"):
        scanrc = os.path.join(get("SAST_SCAN_SRC_DIR"), ".sastscanrc")
        if os.path.exists(scanrc):
            with open(scanrc, "r") as rcfile:
                new_config = json.loads(rcfile.read())
                for key, value in new_config.items():
                    exis_config = get(key)
                    if isinstance(exis_config, dict):
                        exis_config = exis_config.update(value)
                        set(key, exis_config)
                    else:
                        set(key, value)
