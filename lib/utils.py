import os
import tempfile


def find_python_reqfiles(path):
    """
    Method to find python requirements files

    Args:
      path Project dir
    Returns:
      List of python requirement files
    """
    result = []
    req_files = ["requirements.txt", "Pipfile", "Pipfile.lock", "conda.yml"]
    for root, dirs, files in os.walk(path):
        for name in req_files:
            if name in files:
                result.append(os.path.join(root, name))
    return result


def find_jar_files():
    """
    Method to find jar files in the usual maven and gradle directories
    """
    result = []
    jar_lib_path = [
        os.path.join(os.environ["HOME"], ".m2"),
        os.path.join(os.environ["HOME"], ".gradle", "caches"),
    ]
    for path in jar_lib_path:
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(".jar"):
                    result.append(os.path.join(root, file))
    return result


def find_files(src, src_ext_name, use_start=False):
    """
    Method to find files with given extension
    """
    result = []
    for root, dirs, files in os.walk(src):
        for file in files:
            if file == src_ext_name or file.endswith(src_ext_name):
                result.append(os.path.join(root, file))
            elif use_start and file.startswith(src_ext_name):
                result.append(os.path.join(root, file))
    return result


def detect_project_type(src_dir):
    """Detect project type by looking for certain files

    :param src_dir: Source directory

    :return List of detected types
    """
    project_types = ["credscan"]
    depscan_supported = False
    if find_files(src_dir, ".cls"):
        project_types.append("apex")
    if find_python_reqfiles(src_dir):
        project_types.append("python")
        depscan_supported = True
    if find_files(src_dir, ".sql"):
        project_types.append("plsql")
    if find_files(src_dir, ".scala"):
        project_types.append("scala")
    if find_files(src_dir, "pom.xml") or find_files(src_dir, ".gradle"):
        project_types.append("java")
        depscan_supported = True
    if find_files(src_dir, ".jsp"):
        project_types.append("jsp")
        depscan_supported = True
    if find_files(src_dir, "package.json"):
        project_types.append("nodejs")
        depscan_supported = True
    if find_files(src_dir, "go.sum") or find_files(src_dir, "Gopkg.lock"):
        project_types.append("go")
        depscan_supported = True
    if find_files(src_dir, "Cargo.lock"):
        project_types.append("rust")
        depscan_supported = True
    if find_files(src_dir, ".tf"):
        project_types.append("terraform")
    if find_files(src_dir, ".yaml"):
        project_types.append("yaml")
    if (
        find_files(src_dir, ".component")
        or find_files(src_dir, ".cmp")
        or find_files(src_dir, ".page")
    ):
        project_types.append("vf")
    if find_files(src_dir, ".vm"):
        project_types.append("vm")
        depscan_supported = True
    if find_files(src_dir, ".sh"):
        project_types.append("bash")
    if depscan_supported:
        project_types.append("depscan")
    return project_types


def get_report_file(tool_name, reports_dir, convert, ext_name="json"):
    """
    Method to construct a report filename

    Args:
      tool_name Name of the tool
      reports_dir Directory for output reports
      convert Boolean to enable normalisation of reports json
      ext_name Extension for the report
    """
    report_fname = ""
    if reports_dir:
        os.makedirs(reports_dir, exist_ok=True)
        report_fname = os.path.join(reports_dir, tool_name + "-report." + ext_name)
    else:
        fp = tempfile.NamedTemporaryFile(delete=False)
        report_fname = fp.name
    return report_fname
