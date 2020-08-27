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
import os
import sys

runtimeValues = {}

APP_SRC_DIR = os.getenv("APP_SRC_DIR", os.path.join(os.path.dirname(__file__), ".."))
TOOLS_CONFIG_DIR = os.getenv(
    "TOOLS_CONFIG_DIR", os.path.join(os.path.dirname(__file__), "..")
)

# Depth of credscan
credscan_depth = "5"
credscan_config = os.path.join(TOOLS_CONFIG_DIR, "credscan-config.toml")
credscan_timeout = "2m"

# Php memory limit
php_memory_limit = "2G"
phpstan_level = "5"
phpstan_config = os.path.join(TOOLS_CONFIG_DIR, "phpstan.neon.dist")

# Kotlint detekt config
detekt_config = os.path.join(TOOLS_CONFIG_DIR, "detekt-config.yml")
detekt_jar = "/usr/local/bin/detekt-cli.jar"

DEPSCAN_CMD = "/usr/local/bin/depscan"
PMD_CMD = "/opt/pmd-bin/bin/run.sh pmd"
SPOTBUGS_HOME = "/opt/spotbugs"

# Flag to disable telemetry
DISABLE_TELEMETRY = False

# Telemetry server
TELEMETRY_URL = "https://telemetry.appthreat.io/track"

# Line number hash size
HASH_DIGEST_SIZE = 8

# Max lines to show for code snippets
CODE_SNIPPET_MAX_LINES = 3

# ShiftLeft NG SAST CLI command
SHIFTLEFT_NGSAST_CMD = "/opt/sl-cli/sl-latest"

# ShiftLeft URI
SHIFTLEFT_URI = "https://www.shiftleft.io"

# ShiftLeft vulnerabilities api url
SHIFTLEFT_VULN_API = "{}/api/v3/public/org/%(sl_org)s/app/%(app_name)s/version/%(version)s/vulnerabilities".format(
    SHIFTLEFT_URI
)

PR_COMMENT_TEMPLATE = """## Scan Summary

%(summary)s

## Recommendation

%(recommendation)s
"""

PR_COMMENT_BASIC_TEMPLATE = """## Scan Summary

%(summary)s

## Recommendation

%(recommendation)s
"""

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
    "groovy",
    "java",
    "jsp",
    "kotlin",
    "kubernetes",
    "nodejs",
    "plsql",
    "puppet",
    "php",
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
    ".github",
    ".hg",
    "dist",
    "obj",
    "backup",
    "docs",
    "tests",
    "test",
    "test-packages",
    "tmp",
    "report",
    "reports",
    "node_modules",
    ".terraform",
    ".serverless",
    "venv",
    ".virtualenv",
    "vendor",
    "bower_components",
    ".vscode",
    "e2e",
    ".pytest_cache",
    "__pycache__",
    ".storybook",
    ".venv",
    ".tox",
    "examples",
    "tutorials",
    "samples",
    "db_migrations",
    "unittests",
    "unittests_legacy",
]

# Ignore files list
ignore_files = [
    ".pyc",
    ".gz",
    ".tar",
    ".tar.gz",
    ".tar",
    ".md",
    ".log",
    ".tmp",
    ".bin",
    ".exe",
    ".dll",
    ".gif",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".d.ts",
    ".min.js",
    ".min.css",
    ".eslintrc.js",
    ".babelrc.js",
    ".spec.js",
    ".data.js",
    ".bundle.js",
    ".snap",
    ".pb.go",
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
        "source-apex": [
            *get("PMD_CMD").split(" "),
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
            get("TOOLS_CONFIG_DIR") + "/rules-pmd.xml",
        ]
    },
    "arm": {
        "source-arm": [
            "checkov",
            "-s",
            "--quiet",
            "--no-guide",
            "-o",
            "json",
            "-d",
            "%(src)s",
        ]
    },
    "aws": {
        "source-aws": [
            "checkov",
            "-s",
            "--quiet",
            "--no-guide",
            "-o",
            "json",
            "-d",
            "%(src)s",
        ]
    },
    "bom": ["cdxgen", "-r", "-o", "%(report_fname_prefix)s.json", "%(src)s"],
    "credscan": [
        "gitleaks",
        "--config=" + get("credscan_config"),
        "--depth=" + get("credscan_depth"),
        "--repo-path=%(src)s",
        "--redact",
        "--timeout=" + get("credscan_timeout"),
        "--report=%(report_fname_prefix)s.json",
        "--report-format=json",
    ],
    "credscan-raw": [
        "gitleaks",
        "--config=" + get("credscan_config"),
        "--depth=" + get("credscan_depth"),
        "--repo-path=%(src)s",
        "--report=%(report_fname_prefix)s.json",
        "--report-format=json",
    ],
    "credscan-ide": [
        "gitleaks",
        "--config=" + get("credscan_config"),
        "--uncommitted",
        "--repo-path=%(src)s",
        "--timeout=" + get("credscan_timeout"),
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
        "--suggest",
        "--src",
        "%(src)s",
        "--report_file",
        "%(report_fname_prefix)s.json",
    ],
    "go": {
        "source-go": [
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
        "source-jsp": [
            *get("PMD_CMD").split(" "),
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
            get("TOOLS_CONFIG_DIR") + "/rules-pmd.xml",
        ],
        "audit-jsp": [
            "java",
            "-jar",
            get("SPOTBUGS_HOME") + "/lib/spotbugs.jar",
            "-textui",
            "-include",
            get("TOOLS_CONFIG_DIR") + "/spotbugs/include.xml",
            "-exclude",
            get("TOOLS_CONFIG_DIR") + "/spotbugs/exclude.xml",
            "-noClassOk",
            "-sourcepath",
            "%(src)s",
            "-quiet",
            "-medium",
            "-xml:withMessages",
            "-effort:max",
            "-nested:false",
            "-output",
            "%(report_fname_prefix)s.xml",
            "%(src_or_file)s",
        ],
    },
    "kotlin": {
        "source-kt": [
            "java",
            "-jar",
            get("detekt_jar"),
            "-c",
            get("detekt_config"),
            "-i",
            "%(src)s",
            "-r",
            "xml:%(report_fname_prefix)s.xml",
        ],
        "audit-kt": [
            "java",
            "-jar",
            get("SPOTBUGS_HOME") + "/lib/spotbugs.jar",
            "-textui",
            "-include",
            get("TOOLS_CONFIG_DIR") + "/spotbugs/include.xml",
            "-exclude",
            get("TOOLS_CONFIG_DIR") + "/spotbugs/exclude.xml",
            "-noClassOk",
            "-sourcepath",
            "%(src)s",
            "-quiet",
            "-medium",
            "-xml:withMessages",
            "-effort:max",
            "-nested:false",
            "-output",
            "%(report_fname_prefix)s.xml",
            "%(src_or_file)s",
        ],
    },
    "kubernetes": {
        "source-k8s": [
            "checkov",
            "-s",
            "--quiet",
            "--no-guide",
            "-o",
            "json",
            "-d",
            "%(src)s",
        ],
        "kubesec": ["kubesec", "scan", "(filelist=yaml)"],
        "kube-score": [
            "kube-score",
            "score",
            "--output-version",
            "v2",
            "-o",
            "json",
            "(filelist=yaml)",
        ],
    },
    "plsql": {
        "source-sql": [
            *get("PMD_CMD").split(" "),
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
            get("TOOLS_CONFIG_DIR") + "/rules-pmd.xml",
        ]
    },
    "php-ide": {
        "source-php": [
            "phpstan",
            "analyse",
            "-c",
            get("phpstan_config"),
            "-l",
            get("phpstan_level"),
            "--no-progress",
            "--memory-limit",
            get("php_memory_limit"),
            "--error-format=json",
            "%(src)s",
        ],
        "audit-init": ["psalm", "--init", "--root=%(src)s", ".", "1"],
        "audit-php": [
            "psalm",
            "--report-show-info=false",
            "--show-snippet=true",
            "--find-dead-code=always",
            "--find-unused-code=always",
            "-m",
            "--no-progress",
            "--no-file-cache",
            "--no-suggestions",
            "--no-cache",
            "--root=%(src)s",
            "--report=" + "%(report_fname_prefix)s.json",
        ],
        "taint-php": [
            "/opt/phpsast/vendor/bin/psalm",
            "--report-show-info=false",
            "--show-snippet=true",
            "--taint-analysis",
            "-m",
            "--no-progress",
            "--no-file-cache",
            "--no-suggestions",
            "--no-cache",
            "--root=%(src)s",
            "--report=" + "%(report_fname_prefix)s.json",
        ],
    },
    "php": {
        "audit-init": ["psalm", "--init", "--root=%(src)s", ".", "1"],
        "audit-php": [
            "psalm",
            "--report-show-info=false",
            "--show-snippet=true",
            "--find-dead-code=always",
            "--find-unused-code=always",
            "-m",
            "--no-progress",
            "--no-file-cache",
            "--no-suggestions",
            "--no-cache",
            "--root=%(src)s",
            "--report=" + "%(report_fname_prefix)s.json",
        ],
        "taint-php": [
            "/opt/phpsast/vendor/bin/psalm",
            "--report-show-info=false",
            "--show-snippet=true",
            "--taint-analysis",
            "-m",
            "--no-progress",
            "--no-file-cache",
            "--no-suggestions",
            "--no-cache",
            "--root=%(src)s",
            "--report=" + "%(report_fname_prefix)s.json",
        ],
    },
    "puppet": ["puppet-lint", "--error-level", "all", "--json", "%(src)s"],
    "scala": {
        "audit-scala": [
            "java",
            "-jar",
            get("SPOTBUGS_HOME") + "/lib/spotbugs.jar",
            "-textui",
            "-include",
            get("TOOLS_CONFIG_DIR") + "/spotbugs/include.xml",
            "-exclude",
            get("TOOLS_CONFIG_DIR") + "/spotbugs/exclude.xml",
            "-noClassOk",
            "-sourcepath",
            "%(src)s",
            "-quiet",
            "-medium",
            "-xml:withMessages",
            "-effort:max",
            "-nested:false",
            "-output",
            "%(report_fname_prefix)s.xml",
            "%(src_or_file)s",
        ],
    },
    "groovy": {
        "audit-groovy": [
            "java",
            "-jar",
            get("SPOTBUGS_HOME") + "/lib/spotbugs.jar",
            "-textui",
            "-include",
            get("TOOLS_CONFIG_DIR") + "/spotbugs/include.xml",
            "-exclude",
            get("TOOLS_CONFIG_DIR") + "/spotbugs/exclude.xml",
            "-noClassOk",
            "-sourcepath",
            "%(src)s",
            "-quiet",
            "-medium",
            "-xml:withMessages",
            "-effort:max",
            "-nested:false",
            "-output",
            "%(report_fname_prefix)s.xml",
            "%(src_or_file)s",
        ],
    },
    "terraform": {
        "source-tf": [
            "checkov",
            "-s",
            "--quiet",
            "--no-guide",
            "-o",
            "json",
            "-d",
            "%(src)s",
        ],
        "tfsec": ["tfsec", "--format", "json", "--no-colour", "%(src)s"],
    },
    "vf": {
        "source-vf": [
            *get("PMD_CMD").split(" "),
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
            get("TOOLS_CONFIG_DIR") + "/rules-pmd.xml",
        ]
    },
    "vm": {
        "source-vm": [
            *get("PMD_CMD").split(" "),
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
            get("TOOLS_CONFIG_DIR") + "/rules-pmd.xml",
        ]
    },
    "serverless": {
        "source-serverless": [
            "checkov",
            "-s",
            "--quiet",
            "--no-guide",
            "-o",
            "json",
            "-d",
            "%(src)s",
        ],
    },
    "yaml": {
        "yamllint": ["yamllint", "-f", "parsable", "(filelist=yaml)"],
        "source-yaml": [
            "checkov",
            "-s",
            "--quiet",
            "--no-guide",
            "-o",
            "json",
            "-d",
            "%(src)s",
        ],
    },
}

"""
Map of build tools for various language types. Used for auto build feature
"""
build_tools_map = {
    "csharp": ["dotnet", "build"],
    "java": {
        "maven": [get("MVN_CMD"), "compile"],
        "gradle": [get("GRADLE_CMD"), "compileJava"],
        "sbt": ["sbt", "compile"],
    },
    "android": {"gradle": [get("GRADLE_CMD"), "compileDebugSources"]},
    "kotlin": {
        "maven": [get("MVN_CMD"), "compile"],
        "gradle": [get("GRADLE_CMD"), "build"],
    },
    "groovy": {
        "maven": [get("MVN_CMD"), "compile"],
        "gradle": [get("GRADLE_CMD"), "compileGroovy"],
    },
    "scala": {
        "maven": [get("MVN_CMD"), "compile"],
        "gradle": [get("GRADLE_CMD"), "compileScala"],
        "sbt": ["sbt", "compile"],
    },
    "nodejs": {
        "npm": ["npm", "install"],
        "yarn": ["yarn", "install"],
        "rush": ["rush", "install", "--bypass-policy", "--no-link"],
    },
    "go": ["go", "build", "./..."],
    "php": {
        "init": ["composer", "init", "--quiet"],
        "install": ["composer", "install", "-n", "--ignore-platform-reqs"],
        "update": ["composer", "update", "-n", "--ignore-platform-reqs"],
        "autoload": ["composer", "dump-autoload", "-o"],
    },
}

"""
This map contains the SARIF purpose string for various tools
"""
tool_purpose_message = {
    "nodejsscan": "Static Security code scan",
    "njsscan": "Static Security code scan",
    "findsecbugs": "Class File Analyzer",
    "pmd": "Source Code Analyzer",
    "/opt/pmd-bin/bin/run.sh": "Source Code Analyzer",
    "gitleaks": "Secrets Audit",
    "gosec": "Go Security Audit",
    "tfsec": "Terraform Static Analysis",
    "shellcheck": "Shell Script Analysis",
    "bandit": "Security Audit for Python",
    "checkov": "Security Audit for Infrastructure",
    "source-aws": "Security Audit for AWS",
    "source-arm": "Security Audit for Azure Resource Manager",
    "source-k8s": "Kubernetes Security Audit",
    "source-kt": "Kotlin Static Analysis",
    "audit-kt": "Kotlin Security Audit",
    "audit-groovy": "Groovy Security Audit",
    "audit-scala": "Scala Security Audit",
    "detekt": "Kotlin Static Analysis",
    "source-tf": "Terraform Security Audit",
    "source-yaml": "Security Audit for IaC",
    "staticcheck": "Go Static Analysis",
    "source": "Source Aode Analyzer",
    "source-java": "Java Source Analyzer",
    "source-python": "Python Source Analyzer",
    "source-php": "PHP Source Analyzer",
    "phpstan": "PHP Source Analyzer",
    "audit-python": "Python Security Audit",
    "audit-php": "PHP Security Audit",
    "taint-php": "PHP Security Analysis",
    "taint-python": "Python Security Analysis",
    "psalm": "PHP Security Audit",
    "/opt/phpsast/vendor/bin/psalm": "PHP Security Analysis",
    "source-js": "JavaScript Source Analyzer",
    "source-go": "Go Source Analyzer",
    "source-vm": "Apache Velocity Source Analyzer",
    "source-vf": "VisualForce Source Analyzer",
    "source-sql": "SQL Source Analyzer",
    "source-jsp": "JSP Source Analyzer",
    "source-serverless": "Serverless Security Audit",
    "audit-jsp": "JSP Security Audit",
    "source-apex": "Apex Source Analyzer",
    "binary": "Binary byte-code Analyzer",
    "class": "Class File Analyzer",
    "jar": "Jar File Analyzer",
    "cpg": "ShiftLeft NextGen Analyzer",
    "inspect": "ShiftLeft NextGen Analyzer",
    "ng-sast": "ShiftLeft NextGen Analyzer",
}

# Map to link to the reference for the given rule
tool_ref_url = {
    "shellcheck": "https://github.com/koalaman/shellcheck/wiki/SC%(rule_id)s",
    "staticcheck": "https://staticcheck.io/docs/checks#%(rule_id)s",
}

# Rules to ignore
ignored_rules = [
    "GEN001",
    "GEN002",
    "GEN003",
    "AWS002",
    "AWS018",
    "AWS019",
    "Password Hardcoded",
    "Secret Hardcoded",
    "DuplicateArrayKey",
    "DeprecatedFunction",
    "DeprecatedInterface",
    "DeprecatedConstant",
    "DeprecatedMethod",
    "FalsableReturnStatement",
    "ImplicitToStringCast",
    "InternalClass",
    "InternalMethod",
    "InternalProperty",
    "InvalidArgument",
    "InvalidArrayAccess",
    "InvalidArrayAssignment",
    "InvalidArrayOffset",
    "InvalidCast",
    "InvalidCatch",
    "InvalidClass",
    "InvalidExtendClass",
    "InvalidClone",
    "InvalidDocblock",
    "InvalidDocblockParamName",
    "InvalidFalsableReturnType",
    "InvalidFunctionCall",
    "InvalidGlobal",
    "InvalidIterator",
    "InvalidMethodCall",
    "InvalidNullableReturnType",
    "InvalidOperand",
    "InvalidParamDefault",
    "InvalidParent",
    "InvalidPassByReference",
    "InvalidPropertyAssignment",
    "InvalidPropertyAssignmentValue",
    "InvalidPropertyFetch",
    "InvalidReturnStatement",
    "InvalidReturnType",
    "InvalidScalarArgument",
    "InvalidScope",
    "InvalidStaticInvocation",
    "InvalidStringClass",
    "InvalidTemplateParam",
    "InvalidThrow",
    "InvalidToString",
    "MissingClosureParamType",
    "MissingClosureReturnType",
    "MissingConstructor",
    "MissingDependency",
    "MissingDocblockType",
    "MissingFile",
    "MissingImmutableAnnotation",
    "MissingParamType",
    "MissingPropertyType",
    "MissingReturnType",
    "MissingTemplateParam",
    "MissingThrowsDocblock",
    "MismatchingDocblockParamType",
    "MismatchingDocblockReturnType",
    "MixedArgument",
    "MixedArgumentTypeCoercion",
    "MixedArrayAccess",
    "MixedArrayAssignment",
    "MixedArrayOffset",
    "MixedArrayTypeCoercion",
    "MixedAssignment",
    "MixedClone",
    "MixedFunctionCall",
    "MixedInferredReturnType",
    "MixedMethodCall",
    "MixedOperand",
    "MixedPropertyAssignment",
    "MixedPropertyFetch",
    "MixedPropertyTypeCoercion",
    "MixedReturnStatement",
    "MixedReturnTypeCoercion",
    "MixedStringOffsetAssignment",
    "NullableReturnStatement",
    "PossibleRawObjectIteration",
    "PossiblyFalseArgument",
    "PossiblyFalseIterator",
    "PossiblyFalseOperand",
    "PossiblyFalsePropertyAssignmentValue",
    "PossiblyFalseReference",
    "PossiblyInvalidArgument",
    "PossiblyInvalidArrayAccess",
    "PossiblyInvalidArrayAssignment",
    "PossiblyInvalidArrayOffset",
    "PossiblyInvalidCast",
    "PossiblyInvalidFunctionCall",
    "PossiblyInvalidIterator",
    "PossiblyInvalidMethodCall",
    "PossiblyInvalidOperand",
    "PossiblyInvalidPropertyAssignment",
    "PossiblyInvalidPropertyAssignmentValue",
    "PossiblyInvalidPropertyFetch",
    "PossiblyNullArgument",
    "PossiblyNullArrayAccess",
    "PossiblyNullArrayAssignment",
    "PossiblyNullArrayOffset",
    "PossiblyNullFunctionCall",
    "PossiblyNullIterator",
    "PossiblyNullOperand",
    "PossiblyNullPropertyAssignment",
    "PossiblyNullPropertyAssignmentValue",
    "PossiblyNullPropertyFetch",
    "PossiblyNullReference",
    "PossiblyUndefinedArrayOffset",
    "PossiblyUndefinedGlobalVariable",
    "PossiblyUndefinedIntArrayOffset",
    "PossiblyUndefinedMethod",
    "PossiblyUndefinedStringArrayOffset",
    "PossiblyUndefinedVariable",
    "PossiblyUnusedMethod",
    "PossiblyUnusedParam",
    "PossiblyUnusedProperty",
    "PropertyNotSetInConstructor",
    "RedundantCondition",
    "RedundantConditionGivenDocblockType",
    "LessSpecificImplementedReturnType",
    "LessSpecificReturnStatement",
    "LessSpecificReturnType",
    "DocblockTypeContradiction",
    "UndefinedClass",
    "UndefinedConstant",
    "UndefinedDocblockClass",
    "UndefinedFunction",
    "UndefinedGlobalVariable",
    "UndefinedInterface",
    "UndefinedInterfaceMethod",
    "UndefinedMagicMethod",
    "UndefinedMagicPropertyAssignment",
    "UndefinedMagicPropertyFetch",
    "UndefinedMethod",
    "UndefinedPropertyAssignment",
    "UndefinedPropertyFetch",
    "UndefinedThisPropertyAssignment",
    "UndefinedThisPropertyFetch",
    "UndefinedTrait",
    "UndefinedVariable",
    "UnevaluatedCode",
    "UnimplementedAbstractMethod",
    "UnimplementedInterfaceMethod",
    "UninitializedProperty",
    "UnnecessaryVarAnnotation",
    "UnrecognizedExpression",
    "UnrecognizedStatement",
    "UnresolvableInclude",
    "UnusedClass",
    "UnusedClosureParam",
    "UnusedFunctionCall",
    "UnusedMethod",
    "UnusedMethodCall",
    "UnusedParam",
    "UnusedProperty",
    "UnusedPsalmSuppress",
    "UnusedVariable",
    "phpstan-phpdoc",
    "phpstan-constant",
    "phpstan-if",
    "phpstan-property",
    "phpstan-variable",
    "phpstan-negated",
    "phpstan-cannot",
    "phpstan-result",
    "U1000",
]

# Override severity of certain rules
rules_severity = {
    "RCE": "CRITICAL",
    "RCI": "HIGH",
    "SSRF": "CRITICAL",
    "MODULE": "MEDIUM",
    "DIR": "HIGH",
    "SQLI": "CRITICAL",
    "XSS": "MEDIUM",
    "NOSQLI": "HIGH",
    "HHI": "MEDIUM",
    "NODE": "MEDIUM",
    "CKV_AWS_2": "HIGH",
    "CKV_AWS_23": "LOW",
    "CKV_AWS_33": "LOW",
    "CKV_AWS_40": "MEDIUM",
    "CKV_AWS_50": "MEDIUM",
    "CKV_AWS_51": "LOW",
    "AWS007": "HIGH",
    "AWS008": "MEDIUM",
    "AWS009": "HIGH",
    "AWS011": "HIGH",
    "AWS017": "HIGH",
    "CKV_AWS_28": "MEDIUM",
    "CKV_AWS_32": "CRITICAL",
    "CKV_AWS_34": "MEDIUM",
    "CKV_AWS_38": "HIGH",
    "CKV_K8S_14": "MEDIUM",
    "CKV_K8S_21": "CRITICAL",
    "CKV_K8S_27": "CRITICAL",
    "CKV_K8S_29": "MEDIUM",
    "CKV_K8S_34": "CRITICAL",
    "CKV_K8S_4": "CRITICAL",
    "CKV_K8S_5": "CRITICAL",
    "CKV_K8S_6": "CRITICAL",
    "CKV_AWS_46": "CRITICAL",
    "S1005": "LOW",
    "ST1005": "LOW",
    "SA1019": "LOW",
    "ST1020": "LOW",
    "ST1021": "LOW",
    "ST1022": "LOW",
    "ST1011": "LOW",
    "ST1012": "LOW",
    "SA6005": "LOW",
    "SA1029": "LOW",
    "B703": "LOW",
    "B108": "LOW",
    "B201": "LOW",
    "TEMPLATE_INJECTION_FREEMARKER": "MEDIUM",
    "UNVALIDATED_REDIRECT": "MEDIUM",
}


class Cwe(object):
    NOTSET = 0
    IMPROPER_INPUT_VALIDATION = 20
    PATH_TRAVERSAL = 22
    OS_COMMAND_INJECTION = 78
    XSS = 79
    BASIC_XSS = 80
    SQL_INJECTION = 89
    CODE_INJECTION = 94
    IMPROPER_WILDCARD_NEUTRALIZATION = 155
    HARD_CODED_PASSWORD = 259
    IMPROPER_ACCESS_CONTROL = 284
    IMPROPER_CERT_VALIDATION = 295
    CLEARTEXT_TRANSMISSION = 319
    INADEQUATE_ENCRYPTION_STRENGTH = 326
    BROKEN_CRYPTO = 327
    INSUFFICIENT_RANDOM_VALUES = 330
    INSECURE_TEMP_FILE = 377
    DESERIALIZATION_OF_UNTRUSTED_DATA = 502
    MULTIPLE_BINDS = 605
    IMPROPER_CHECK_OF_EXCEPT_COND = 703
    INCORRECT_PERMISSION_ASSIGNMENT = 732

    MITRE_URL_PATTERN = "https://cwe.mitre.org/data/definitions/%s.html"

    def __init__(self, id=NOTSET):
        self.id = id

    def link(self):
        if self.id == Cwe.NOTSET:
            return ""

        return Cwe.MITRE_URL_PATTERN % str(self.id)

    def __str__(self):
        if self.id == Cwe.NOTSET:
            return ""
        return "CWE-%i" % (self.id)

    def as_dict(self):
        return {"id": self.id, "link": self.link()} if self.id != Cwe.NOTSET else {}

    def as_jsons(self):
        return str(self.as_dict())

    def from_dict(self, data):
        if "id" in data:
            self.id = int(data["id"])
        else:
            self.id = Cwe.NOTSET

    def __eq__(self, other):
        return self.id == other.id

    def __ne__(self, other):
        return self.id != other.id

    def __hash__(self):
        return id(self)


CWEMAP = {
    "B000": Cwe.NOTSET,
    "LEGACY": Cwe.NOTSET,
    # Plugins
    "B101": Cwe.IMPROPER_CHECK_OF_EXCEPT_COND,
    "B102": Cwe.OS_COMMAND_INJECTION,
    "B103": Cwe.INCORRECT_PERMISSION_ASSIGNMENT,
    "B104": Cwe.MULTIPLE_BINDS,
    "B105": Cwe.HARD_CODED_PASSWORD,
    "B108": Cwe.INSECURE_TEMP_FILE,
    "B110": Cwe.IMPROPER_CHECK_OF_EXCEPT_COND,
    "B112": Cwe.IMPROPER_CHECK_OF_EXCEPT_COND,
    "B201": Cwe.CODE_INJECTION,
    "B324": Cwe.BROKEN_CRYPTO,
    "B501": Cwe.IMPROPER_CERT_VALIDATION,
    "B502": Cwe.BROKEN_CRYPTO,
    "B503": Cwe.BROKEN_CRYPTO,
    "B504": Cwe.BROKEN_CRYPTO,
    "B505": Cwe.INADEQUATE_ENCRYPTION_STRENGTH,
    "B506": Cwe.IMPROPER_INPUT_VALIDATION,
    "B507": Cwe.IMPROPER_CERT_VALIDATION,
    "B601": Cwe.OS_COMMAND_INJECTION,
    "B602": Cwe.OS_COMMAND_INJECTION,
    "B603": Cwe.OS_COMMAND_INJECTION,
    "B604": Cwe.OS_COMMAND_INJECTION,
    "B605": Cwe.OS_COMMAND_INJECTION,
    "B606": Cwe.OS_COMMAND_INJECTION,
    "B607": Cwe.OS_COMMAND_INJECTION,
    "B608": Cwe.SQL_INJECTION,
    "B609": Cwe.IMPROPER_WILDCARD_NEUTRALIZATION,
    "B611": Cwe.SQL_INJECTION,
    "B701": Cwe.CODE_INJECTION,
    "B702": Cwe.BASIC_XSS,
    "B703": Cwe.BASIC_XSS,
    # Calls
    "B301": Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA,
    "B302": Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA,
    "B303": Cwe.BROKEN_CRYPTO,
    "B304": Cwe.BROKEN_CRYPTO,
    "B305": Cwe.BROKEN_CRYPTO,
    "B306": Cwe.INSECURE_TEMP_FILE,
    "B307": Cwe.OS_COMMAND_INJECTION,
    "B308": Cwe.XSS,
    "B309": Cwe.CLEARTEXT_TRANSMISSION,
    "B310": Cwe.PATH_TRAVERSAL,
    "B311": Cwe.INSUFFICIENT_RANDOM_VALUES,
    "B312": Cwe.CLEARTEXT_TRANSMISSION,
    "B313": Cwe.IMPROPER_INPUT_VALIDATION,
    "B314": Cwe.IMPROPER_INPUT_VALIDATION,
    "B315": Cwe.IMPROPER_INPUT_VALIDATION,
    "B316": Cwe.IMPROPER_INPUT_VALIDATION,
    "B317": Cwe.IMPROPER_INPUT_VALIDATION,
    "B318": Cwe.IMPROPER_INPUT_VALIDATION,
    "B319": Cwe.IMPROPER_INPUT_VALIDATION,
    "B320": Cwe.IMPROPER_INPUT_VALIDATION,
    "B321": Cwe.CLEARTEXT_TRANSMISSION,
    "B322": Cwe.OS_COMMAND_INJECTION,
    "B323": Cwe.IMPROPER_CERT_VALIDATION,
    "B325": Cwe.INSECURE_TEMP_FILE,
    # Imports
    "B401": Cwe.CLEARTEXT_TRANSMISSION,
    "B402": Cwe.CLEARTEXT_TRANSMISSION,
    "B403": Cwe.DESERIALIZATION_OF_UNTRUSTED_DATA,
    "B404": Cwe.OS_COMMAND_INJECTION,
    "B405": Cwe.IMPROPER_INPUT_VALIDATION,
    "B406": Cwe.IMPROPER_INPUT_VALIDATION,
    "B407": Cwe.IMPROPER_INPUT_VALIDATION,
    "B408": Cwe.IMPROPER_INPUT_VALIDATION,
    "B409": Cwe.IMPROPER_INPUT_VALIDATION,
    "B410": Cwe.IMPROPER_INPUT_VALIDATION,
    "B411": Cwe.IMPROPER_INPUT_VALIDATION,
    "B412": Cwe.IMPROPER_ACCESS_CONTROL,
    "B413": Cwe.BROKEN_CRYPTO,
    "B414": Cwe.BROKEN_CRYPTO,
}

# Mapping of rules and owasp category
rules_owasp_category = {
    "CKV_": "a6-misconfiguration",
    "AWS": "a6-misconfiguration",
    "CWE-20": "a1-injection",
    "CWE-22": "a5-broken-access-control",
    "CWE-78": "a1-injection",
    "CWE-79": "a7-xss",
    "CWE-80": "a7-xss",
    "CWE-89": "a1-injection",
    "CWE-91": "a1-injection",
    "CWE-94": "a1-injection",
    "CWE-155": "a1-injection",
    "CWE-117": "a3-sensitive-data-exposure",
    "CWE-203": "a3-sensitive-data-exposure",
    "CWE-259": "a3-sensitive-data-exposure",
    "CWE-284": "a5-broken-access-control",
    "CWE-295": "a3-sensitive-data-exposure",
    "CWE-319": "a3-sensitive-data-exposure",
    "CWE-326": "a3-sensitive-data-exposure",
    "CWE-327": "a3-sensitive-data-exposure",
    "CWE-330": "a2-broken-authentication",
    "CWE-377": "a6-misconfiguration",
    "CWE-502": "a8-deserialization",
    "CWE-601": "a6-misconfiguration",
    "CWE-605": "a6-misconfiguration",
    "CWE-644": "a6-misconfiguration",
    "CWE-703": "a6-misconfiguration",
    "CWE-732": "a6-misconfiguration",
    "CWE-918": "a6-misconfiguration",
    "rce": "a1-injection",
    "sqli": "a1-injection",
    "nosqli": "a1-injection",
    "xmli": "a1-injection",
    "xss": "a7-xss",
    "basic-xss": "a7-xss",
    "broken-access-control": "a5-broken-access-control",
    "file-write": "a5-broken-access-control",
    "traversal": "a5-broken-access-control",
    "ssrf": "a6-misconfiguration",
    "open-redirect": "a6-misconfiguration",
    "server-data-leak": "a3-sensitive-data-exposure",
    "user-data-leak": "a3-sensitive-data-exposure",
    "user-response": "a6-misconfiguration",
    "data-leak-log": "a3-sensitive-data-exposure",
    "ssti": "a1-injection",
    "misconfiguration-": "a6-misconfiguration",
}

# Build break rules
build_break_rules = {"default": {"max_critical": 0, "max_high": 2, "max_medium": 5}}

# URL for viewing reports online
hosted_viewer_uri = "https://sarifviewer.azurewebsites.net"

# Suppression markers
suppress_markers = ["nosec", "nolint", "scan:ignore", "sl:ignore"]


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
