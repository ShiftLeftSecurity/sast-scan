"""
Multi-language static analysis scanner
"""
import argparse
import os
import subprocess
import sys
import tempfile

"""
Supported language scan types
"""
scan_types = [
    "ansible",
    "aws",
    "bash",
    "credscan",
    "golang",
    "java",
    "kotlin",
    "nodejs",
    "puppet",
    "python",
    "ruby",
    "rust",
    "terraform",
    "yaml",
]

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
]


def build_args():
    """
    Constructs command line arguments for the scanner
    """
    parser = argparse.ArgumentParser(
        description="Wrapper for various static analysis tools"
    )
    parser.add_argument("--src", dest="src_dir", help="Source directory", required=True)
    parser.add_argument("--out_dir", dest="reports_dir", help="Reports directory")
    parser.add_argument(
        "--type",
        dest="scan_type",
        choices=scan_types,
        help="Override project type if auto-detection is incorrect",
    )
    parser.add_argument(
        "--convert",
        action="store_true",
        dest="convert",
        help="Convert results to a normalized json lines format",
    )
    return parser.parse_args()


def scan(type, src, reports_dir, convert):
    """

    """
    if type:
        getattr(sys.modules[__name__], "%s_scan" % type)(src, reports_dir, convert)


def exec_tool(args):
    """

    """
    subprocess.run(args, stderr=subprocess.STDOUT)


def get_report_file(tool_name, reports_dir, convert, ext_name="json"):
    """

    """
    report_fname = ""
    if reports_dir:
        report_fname = os.path.join(reports_dir, tool_name + "-report." + ext_name)
    else:
        fp = tempfile.NamedTemporaryFile(delete=False)
        report_fname = fp.name
    return report_fname


def python_scan(src, reports_dir, convert):
    """

    """
    bandit_scan(src, reports_dir, convert)
    ossaudit_scan(src, reports_dir, convert)
    python_bom(src, reports_dir, convert)


def bandit_scan(src, reports_dir, convert):
    """

    """
    CONVERT_ARGS = []
    report_fname = get_report_file("bandit", reports_dir, convert)
    if reports_dir or convert:
        CONVERT_ARGS = ["-o", report_fname, "-f", "json"]
    BANDIT_CMD = "bandit"
    BANDIT_ARGS = [
        BANDIT_CMD,
        "-r",
        "-ii",
        "-ll",
        *CONVERT_ARGS,
        "-x",
        ",".join(ignore_directories),
        src,
    ]
    exec_tool(BANDIT_ARGS)


def find_python_reqfiles(path):
    """

    """
    result = []
    REQ_FILES = ["requirements.txt", "Pipfile", "Pipfile.lock", "conda.yml"]
    for root, dirs, files in os.walk(path):
        for name in REQ_FILES:
            if name in files:
                result.append(os.path.join(root, name))
    return result


def ossaudit_scan(src, reports_dir, convert):
    """

    """
    reqfiles = find_python_reqfiles(src)
    if not reqfiles:
        return
    AARGS = []
    for req in reqfiles:
        AARGS.append("-f")
        AARGS.append(req)
    OSS_CMD = "ossaudit"
    OSS_ARGS = [OSS_CMD, *AARGS]
    for c in "cve,name,version,cvss_score,title,description".split(","):
        OSS_ARGS.append("--column")
        OSS_ARGS.append(c)
    exec_tool(OSS_ARGS)


def python_bom(src, reports_dir, convert):
    """

    """
    REQ_FILE = os.path.join(src, "requirements.txt")
    if not os.path.exists(REQ_FILE):
        return
    report_fname = get_report_file("python-bom", reports_dir, convert, ext_name="xml")
    BOM_ARGS = ["cyclonedx-py", "-i", REQ_FILE, "-o", report_fname]
    exec_tool(BOM_ARGS)


def java_scan(src, reports_dir, convert):
    """

    """
    pmd_scan(src, reports_dir, convert)
    dep_check_scan(src, reports_dir, convert)


def pmd_scan(src, reports_dir, convert):
    """

    """
    CONVERT_ARGS = []
    report_fname = get_report_file("pmd", reports_dir, convert, ext_name="csv")
    if reports_dir or convert:
        CONVERT_ARGS = ["-r", report_fname, "-f", "csv"]
    PMD_CMD = os.environ["PMD_CMD"].split(" ")
    PMD_ARGS = [
        *PMD_CMD,
        "-d",
        src,
        *CONVERT_ARGS,
        "-R",
        "/usr/local/src/rules-pmd.xml",
    ]
    exec_tool(PMD_ARGS)


def dep_check_scan(src, reports_dir, convert):
    """

    """
    CONVERT_ARGS = []
    report_fname = get_report_file("dep_check", reports_dir, convert)
    if reports_dir or convert:
        CONVERT_ARGS = ["-o", report_fname, "-f", "JSON"]
    DC_CMD = "/opt/dependency-check/bin/dependency-check.sh"
    DC_ARGS = [
        DC_CMD,
        "-s",
        src,
        *CONVERT_ARGS,
        "--enableExperimental",
        "--exclude",
        ",".join(ignore_directories),
    ]
    exec_tool(DC_ARGS)


def nodejs_scan(src, reports_dir, convert):
    """

    """
    retirejs_scan(src, reports_dir, convert)
    nodejs_bom(src, reports_dir, convert)


def retirejs_scan(src, reports_dir, convert):
    """

    """
    CONVERT_ARGS = []
    report_fname = get_report_file("retire", reports_dir, convert)
    if reports_dir or convert:
        CONVERT_ARGS = ["--outputpath", report_fname, "--outputformat", "json"]
    RETIRE_CMD = "retire"
    RETIRE_ARGS = [
        RETIRE_CMD,
        "--path",
        src,
        "-p",
        *CONVERT_ARGS,
        "--ignore",
        ",".join(ignore_directories),
    ]
    exec_tool(RETIRE_ARGS)


def nodejs_bom(src, reports_dir, convert):
    """

    """
    report_fname = get_report_file("nodejs-bom", reports_dir, convert, ext_name="xml")
    BOM_ARGS = ["cyclonedx-bom", "-o", report_fname, "-d", src]
    exec_tool(BOM_ARGS)


if __name__ == "__main__":
    args = build_args()
    type = args.scan_type
    scan(type, args.src_dir, args.reports_dir, args.convert)
