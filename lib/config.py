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
        "-out=%(report_fname_prefix)s.json",
        "%(src)s",
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
    "terraform": ["tfsec", "--no-colour", "%(src)s"],
    "yaml": ["yamllint", "-f", "parsable", "(filelist=yaml)"],
}


"""
This map contains the purpose string for various tools
"""
tool_purpose_message = {
    "nodejsscan": "Static security code scan powered by NodeJsScan",
    "findsecbugs": "Security audit powered by Find Security Bugs",
    "pmd": "Static code analysis powered by PMD",
    "credscan": "Secrets audit powered by gitleaks",
}
