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

import os
import re
import shutil
import tempfile
import zipfile
from hashlib import blake2b
from pathlib import Path

import lib.config as config

HASH_DIGEST_SIZE = 16


def filter_ignored_dirs(dirs):
    """
    Method to filter directory list to remove ignored directories
    :param dirs: Directories to ignore
    :return: Filtered directory list
    """
    [
        dirs.remove(d)
        for d in list(dirs)
        if d.lower() in config.ignore_directories or d.startswith(".")
    ]
    return dirs


def is_ignored_dir(base_dir, dir_name):
    """
    Method to find if the given directory is an ignored directory
    :param base_dir: Base directory
    :param dir_name: Directory to compare
    :return: Boolean True if directory can be ignored. False otherwise
    """
    base_dir = base_dir.lower()
    dir_name = dir_name.lower()
    if dir_name.startswith("."):
        return True
    elif dir_name.startswith("/" + base_dir):
        dir_name = re.sub(r"^/" + base_dir + "/", "", dir_name)
    elif dir_name.startswith(base_dir):
        dir_name = re.sub(r"^" + base_dir + "/", "", dir_name)
    for d in config.ignore_directories:
        if dir_name == d or dir_name.startswith(d) or ("/" + d + "/") in dir_name:
            return True
    return False


def is_ignored_file(base_dir, file_name):
    """
    Method to find if the given file can be ignored
    :param base_dir: Base directory
    :param file_name: File to compare
    :return: Boolean True if file can be ignored. False otherwise
    """
    if not file_name:
        return False
    file_name = file_name.lower()
    extn = "".join(Path(file_name).suffixes)
    if extn in config.ignore_files or file_name in config.ignore_files:
        return True
    for ie in config.ignore_files:
        if file_name.endswith(ie):
            return True
    return False


def find_path_prefix(base_dir, file_name):
    """
    Method to find path prefix by looking up the filename from the base_dir

    :param base_dir: Base directory to search
    :param file_name: Filename to search
    :return: Path prefix to be added to the filename
    """
    file_path_obj = Path(file_name)
    base_dir_obj = Path(base_dir)
    if file_path_obj.is_absolute():
        return ""
    tmpf = os.path.join(base_dir, file_name)
    if os.path.exists(tmpf):
        return ""
    for f in base_dir_obj.rglob(file_path_obj.name):
        if not is_ignored_dir(base_dir, f.parent.name):
            ppath = f.as_posix()
            if ppath.endswith(file_path_obj.name):
                retpath = re.sub("^" + base_dir + "/", "", ppath)
                return retpath.replace("/" + file_name, "")
    return ""


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
        filter_ignored_dirs(dirs)
        if not is_ignored_dir(path, root):
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
            filter_ignored_dirs(dirs)
            if not is_ignored_dir(path, root):
                for file in files:
                    if file.endswith(".jar"):
                        result.append(os.path.join(root, file))
    return result


def find_files(src, src_ext_name, use_start=False, quick=False):
    """
    Method to find files with given extension
    :param src: Source directory
    :param src_ext_name: Extension
    :param use_start: Boolean to check for file prefix
    :return: List of files with full path
    """
    result = []
    for root, dirs, files in os.walk(src):
        filter_ignored_dirs(dirs)
        if not is_ignored_dir(src, root):
            for file in files:
                if is_ignored_file(src, file):
                    continue
                if file == src_ext_name or file.endswith(src_ext_name):
                    result.append(os.path.join(root, file))
                elif use_start and file.startswith(src_ext_name):
                    result.append(os.path.join(root, file))
                if quick and result:
                    return result
    return result


def find_java_artifacts(search_dir):
    """
    Method to find java artifacts in the given directory
    :param src: Directory to search
    :return: List of war or ear or jar files
    """
    result = [p.as_posix() for p in Path(search_dir).rglob("*.war")]
    if not result:
        result = [p.as_posix() for p in Path(search_dir).rglob("*.ear")]
    if not result:
        result = [p.as_posix() for p in Path(search_dir).rglob("*.jar")]
    # Zip up the target directory as a jar file for analysis
    if not result:
        is_empty = True
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jar", encoding="utf-8", delete=False
        ) as zfile:
            with zipfile.ZipFile(zfile.name, "w") as zf:
                for dirname, subdirs, files in os.walk(search_dir):
                    zf.write(dirname)
                    is_empty = False
                    for filename in files:
                        if not filename.endswith(".jar"):
                            zf.write(os.path.join(dirname, filename))
        return [] if is_empty else [zfile.name]
    return result


def find_csharp_artifacts(search_dir):
    """
    Method to find .Net and .Net core project files in the given directory
    :param src: Directory to search
    :return: List of war or ear or jar files
    """
    result = [p.as_posix() for p in Path(search_dir).rglob("*.csproj")]
    if not result:
        result = [p.as_posix() for p in Path(search_dir).rglob("*.sln")]
    return result


def detect_project_type(src_dir, scan_mode):
    """Detect project type by looking for certain files

    :param src_dir: Source directory

    :return List of detected types
    """
    project_types = []
    if scan_mode == "ide":
        project_types.append("credscan-ide")
    else:
        project_types.append("credscan")
    depscan_supported = False
    if (
        "docker.io" in src_dir
        or "quay.io" in src_dir
        or ":latest" in src_dir
        or "@sha256" in src_dir
        or src_dir.endswith(".tar")
        or src_dir.endswith(".tar.gz")
    ):
        project_types.append("docker")
    if find_files(src_dir, ".cls", False, True):
        project_types.append("apex")
    if find_python_reqfiles(src_dir) or find_files(src_dir, ".py", False, True):
        project_types.append("python")
        depscan_supported = True
    if find_files(src_dir, ".sql", False, True):
        project_types.append("plsql")
    if find_files(src_dir, "composer.json", False, True) or find_files(
        src_dir, ".php", False, True
    ):
        project_types.append("php")
        depscan_supported = True
    if find_files(src_dir, ".sbt", False, True) or find_files(
        src_dir, ".scala", False, True
    ):
        project_types.append("scala")
        depscan_supported = True
    if find_files(src_dir, ".kt", False, True) or find_files(
        src_dir, ".kts", False, True
    ):
        project_types.append("kotlin")
        depscan_supported = True
    if (
        find_files(src_dir, "pom.xml", False, True)
        or find_files(src_dir, ".gradle", False, True)
        or os.environ.get("SHIFTLEFT_LANG_JAVA")
    ):
        if "kotlin" not in project_types:
            project_types.append("java")
            depscan_supported = True
    if find_files(src_dir, ".jsp", False, True):
        project_types.append("jsp")
        depscan_supported = True
    if (
        find_files(src_dir, "package.json", False, True)
        or find_files(src_dir, "yarn.lock", False, True)
        or find_files(src_dir, ".js", False, True)
    ):
        if find_files(src_dir, ".ts", False, True):
            project_types.append("ts")
        project_types.append("nodejs")
        depscan_supported = True
    if (
        find_files(src_dir, ".csproj", False, True)
        or find_files(src_dir, ".sln", False, True)
        or os.environ.get("SHIFTLEFT_LANG_CSHARP")
    ):
        project_types.append("csharp")
        depscan_supported = True
    if find_files(src_dir, "go.sum", False, True) or find_files(
        src_dir, "Gopkg.lock", False, True
    ):
        project_types.append("go")
        depscan_supported = True
    if find_files(src_dir, "Cargo.lock", False, True):
        project_types.append("rust")
        depscan_supported = True
    if find_files(src_dir, "Gemfile", False, True) or find_files(
        src_dir, "Gemfile.lock", False, True
    ):
        project_types.append("ruby")
        depscan_supported = True
    if find_files(src_dir, "serverless.yml", False, True):
        project_types.append("serverless")
    if find_files(src_dir, "Dockerfile", True, True):
        project_types.append("dockerfile")
    if find_files(src_dir, "deploy.json", False, True) or find_files(
        src_dir, "parameters.json", False, True
    ):
        project_types.append("arm")
    if find_files(src_dir, ".tf", False, True) or find_files(
        src_dir, ".tf.json", False, True
    ):
        project_types.append("terraform")
    if find_files(src_dir, ".yaml", False, True) or find_files(
        src_dir, ".yml", False, True
    ):
        project_types.append("yaml")
    if (
        find_files(src_dir, ".component", False, True)
        or find_files(src_dir, ".cmp", False, True)
        or find_files(src_dir, ".page", False, True)
    ):
        project_types.append("vf")
    if find_files(src_dir, ".vm", False, True):
        project_types.append("vm")
        depscan_supported = True
    if find_files(src_dir, ".sh", False, True):
        project_types.append("bash")
    if depscan_supported and scan_mode != "ide":
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


def get_workspace(repo_context):
    """
    Construct the workspace url from the given repo context

    :param repo_context: Repo context from context.py
    :return: Workspace url for known VCS or None
    """
    if not repo_context["repositoryUri"]:
        return None
    revision = repo_context.get("revisionId", repo_context.get("branch"))
    if "github" in repo_context["repositoryUri"]:
        return "{}/blob/{}".format(repo_context["repositoryUri"], revision)
    if "gitlab" in repo_context["repositoryUri"]:
        return "{}/-/blob/{}".format(repo_context["repositoryUri"], revision)
    if "bitbucket" in repo_context["repositoryUri"] and repo_context.get("revisionId"):
        return "{}/src/{}".format(repo_context["repositoryUri"], revision)
    if "azure.com" in repo_context["repositoryUri"] and repo_context.get("branch"):
        return "{}?_a=contents&version=GB{}&path=".format(
            repo_context["repositoryUri"], repo_context.get("branch")
        )
    return None


def is_generic_package(filePath):
    """
    Method to determine if the filename belongs to any oss package.
    Very basic and just checks for things that begin with java or org
    :param filePath: filePath to check
    :return: True if the filename begins with java or org. False otherwise
    """
    if not filePath:
        return True
    oss_package_prefixes = ["java", "org", "microsoft"]
    for p in oss_package_prefixes:
        if filePath.lower().startswith(p):
            return True
    return False


def check_dotnet():
    """
    Method to check if dotnet is available

    :return True if dotnet command is available. False otherwise
    """
    return check_command("dotnet")


def check_command(cmd):
    """
    Method to check if command is available

    :return True if command is available in PATH. False otherwise
    """
    try:
        cpath = shutil.which(cmd, mode=os.F_OK | os.X_OK)
        return cpath is not None
    except Exception:
        return False


def calculate_line_hash(filename, lineno, end_lineno, line, short_desc):
    """
    Method to calculate line hash

    :param lineno: Line number
    :param end_lineno: End Line number
    :param filename: File name
    :param line: Line to hash
    :return: Hash based on blake2b algorithm
    """
    snippet = "{}:{}:{}:{}:{}".format(
        lineno,
        end_lineno,
        filename,
        line.strip().replace("\t", "").replace("\n", ""),
        short_desc,
    )
    h = blake2b(digest_size=HASH_DIGEST_SIZE)
    h.update(snippet.encode())
    return h.hexdigest()


def to_fingerprint_hash(str_to_hash, digest_size):
    """
    Method to calculate fingerprint hash

    :param str_to_hash: String to hash
    :param digest_size: Digest size
    """
    h = blake2b(digest_size=digest_size)
    h.update(str_to_hash.encode())
    return h.hexdigest()


def get_env():
    env = os.environ.copy()
    if (os.getenv("USE_JAVA_8") or os.getenv("WITH_JAVA_8")) and os.getenv(
        "SCAN_JAVA_8_HOME"
    ):
        env["SCAN_JAVA_HOME"] = os.getenv("SCAN_JAVA_8_HOME")
    elif os.getenv("SCAN_JAVA_11_HOME"):
        env["SCAN_JAVA_HOME"] = os.getenv("SCAN_JAVA_11_HOME")
    return env
