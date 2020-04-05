import json
import logging
import os
import sys


LOG = logging.getLogger(__name__)

runtimeValues = {}

# Depth of credscan
credscan_depth = "2"

DEPSCAN_CMD = "/usr/local/bin/depscan"

# Flag to disable telemetry
DISABLE_TELEMETRY = False

# Telemetry server
TELEMETRY_URL = "https://telemetry.appthreat.io/track"

"""
Supported language scan types
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
]


def get(configName, default_value=None):
    """Method to retrieve a config given a name. This method lazy loads configuration
    values and helps with overriding using a local config

    :param configName: Name of the config
    :return Config value
    """
    try:
        value = runtimeValues.get(configName)
        if not value:
            value = os.environ.get(configName.upper())
        if not value:
            value = getattr(sys.modules[__name__], configName, None)
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
        "pmd": [
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
        "--depth=" + get("credscan_depth"),
        "--repo-path=%(src)s",
        "--redact",
        "--timeout=2m",
        "--report=%(report_fname_prefix)s.json",
        "--report-format=json",
    ],
    "credscan-ide": [
        "gitleaks",
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
        "pmd": [
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
        "pmd": [
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
        "pmd": [
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
        "pmd": [
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
    "nodejsscan": "Static security code scan by NodeJsScan",
    "findsecbugs": "Security audit by Find Security Bugs",
    "pmd": "Static code analysis by PMD",
    "/opt/pmd-bin/bin/run.sh": "Static code analysis by PMD",
    "gitleaks": "Secrets audit by gitleaks",
    "gosec": "Go security checks by gosec",
    "tfsec": "Terraform static analysis by tfsec",
    "shellcheck": "Shell script analysis by shellcheck",
    "bandit": "Security audit for python by bandit",
    "staticcheck": "Go static analysis",
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
