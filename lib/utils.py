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


def is_ignored_dir(base_dir, dir_name):
    """
    Method to find if the given directory is an ignored directory
    :param base_dir: Base directory
    :param dir_name: Directory to compare
    :return:
    """
    if dir_name.startswith("/" + base_dir):
        dir_name = re.sub(r"^/" + base_dir + "/", "", dir_name)
    elif dir_name.startswith(base_dir):
        dir_name = re.sub(r"^" + base_dir + "/", "", dir_name)
    for d in config.ignore_directories:
        if dir_name == d or dir_name.startswith(d):
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
            if not is_ignored_dir(path, root):
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
        if not is_ignored_dir(src, root):
            for file in files:
                if file == src_ext_name or file.endswith(src_ext_name):
                    result.append(os.path.join(root, file))
                elif use_start and file.startswith(src_ext_name):
                    result.append(os.path.join(root, file))
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
    if find_files(src_dir, ".cls"):
        project_types.append("apex")
    if find_python_reqfiles(src_dir) or find_files(src_dir, ".py"):
        project_types.append("python")
        depscan_supported = True
    if find_files(src_dir, ".sql"):
        project_types.append("plsql")
    if find_files(src_dir, ".scala"):
        project_types.append("scala")
    if (
        find_files(src_dir, "pom.xml")
        or find_files(src_dir, ".gradle")
        or os.environ.get("SHIFTLEFT_LANG_JAVA")
    ):
        project_types.append("java")
        depscan_supported = True
    if find_files(src_dir, ".jsp"):
        project_types.append("jsp")
        depscan_supported = True
    if (
        find_files(src_dir, "package.json")
        or find_files(src_dir, "yarn.lock")
        or find_files(src_dir, ".js")
    ):
        project_types.append("nodejs")
        depscan_supported = True
    if (
        find_files(src_dir, ".csproj")
        or find_files(src_dir, ".sln")
        or os.environ.get("SHIFTLEFT_LANG_CSHARP")
    ):
        project_types.append("csharp")
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
    if "github.com" in repo_context["repositoryUri"]:
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


def calculate_line_hash(line):
    """
    Method to calculate line hash
    :param line: Line to hash
    :return: Hash based on blake2b algorithm
    """
    snippet = line.strip().replace("\t", "").replace("\n", "")
    h = blake2b(digest_size=HASH_DIGEST_SIZE)
    h.update(snippet.encode())
    return h.hexdigest()
