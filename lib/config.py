import json
import logging
import os
import sys


LOG = logging.getLogger(__name__)

runtimeValues = {}

"""
Supported language scan types
"""
scan_types = [
    "ansible",
    "aws",
    "bash",
    "bom",
    "credscan",
    "golang",
    "java",
    "kotlin",
    "kubernetes",
    "nodejs",
    "puppet",
    "python",
    "ruby",
    "rust",
    "terraform",
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
    "aws": ["cfn-lint", "-f", "json", "-e", "%(src)s/**/*.yaml"],
    "bom": ["cdxgen", "-o", "%(report_fname_prefix)s.xml", "%(src)s"],
    "credscan": [
        "gitleaks",
        "--repo-path=%(src)s",
        "--redact",
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
        "info",
        "--color=never",
        "(filelist=sh)",
    ],
    "golang": [
        "gosec",
        "-fmt=json",
        "-confidence=medium",
        "-severity=medium",
        "-no-fail",
        "-out=%(report_fname_prefix)s.json",
        "./...",
    ],
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
    "puppet": ["puppet-lint", "--error-level", "all", "--json", "%(src)s"],
    "ruby": [
        "railroader",
        "--skip-files",
        ",".join(ignore_directories),
        "-o",
        "%(report_fname_prefix)s.json",
        "-q",
        "%(src)s",
    ],
    "rust": ["cargo-audit", "audit", "-q", "--json", "-c", "never"],
    "terraform": ["tfsec", "--format", "json", "--no-colour", "%(src)s"],
    "yaml": ["yamllint", "-f", "parsable", "(filelist=yaml)"],
}


"""
This map contains the purpose string for various tools
"""
tool_purpose_message = {
    "nodejsscan": "Static security code scan by NodeJsScan",
    "findsecbugs": "Security audit by Find Security Bugs",
    "pmd": "Static code analysis by PMD",
    "gitleaks": "Secrets audit by gitleaks",
    "gosec": "Golang security checks by gosec",
    "tfsec": "Terraform static analysis by tfsec",
    "shellcheck": "Shell script analysis by shellcheck",
    "bandit": "Security audit for python by bandit",
}

# Map to link to the reference for the given rule
tool_ref_url = {
    "shellcheck": "https://github.com/koalaman/shellcheck/wiki/SC%(rule_id)s",
    "gosec": "https://github.com/securego/gosec#available-rules",
}

# Build break rules
build_break_rules = {"default": {"max_critical": 0, "max_high": 2, "max_medium": 5}}

# URL for viewing reports online
hosted_viewer_uri = "https://sarifviewer.azurewebsites.net"


def get(configName, default_value=None):
    """Method to retrieve a config given a name. This method lazy loads configuration
    values and helps with overriding using a local config

    :param configName: Name of the config
    :return Config value
    """
    try:
        value = runtimeValues.get(configName)
        if not value:
            value = os.environ.get(configName)
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
