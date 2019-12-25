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


if __name__ == "__main__":
    args = build_args()
    type = args.scan_type
    scan(type, args.src_dir, args.reports_dir, args.convert)
