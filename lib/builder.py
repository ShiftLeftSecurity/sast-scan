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
import stat
import subprocess
import sys
from pathlib import Path

from lib.config import build_tools_map
from lib.executor import exec_tool
from lib.logger import LOG
from lib.utils import find_files, get_env


def get_gradle_cmd(src, cmd_args):  # scan:ignore
    # Check for the presence of local gradle wrapper
    fullPath = os.path.join(src, "gradlew")
    if os.path.exists(fullPath):
        try:
            os.chmod(
                fullPath,
                stat.S_IRUSR
                | stat.S_IWUSR
                | stat.S_IXUSR
                | stat.S_IRGRP
                | stat.S_IWGRP
                | stat.S_IROTH,
            )
        except Exception:
            LOG.debug("Ensure {} has execute permissions".format(fullPath))
        cmd_args[0] = fullPath
    return cmd_args


def auto_build(type_list, src, reports_dir):  # scan:ignore
    """
    Automatically build project identified by type

    :param type_list: Project types
    :param src: Source directory
    :param reports_dir: Reports directory to store any logs

    :return: boolean status from the build. True if the command executed successfully. False otherwise
    """
    ret = True
    if os.getenv("SHIFTLEFT_ANALYZE_FILE"):
        return True
    for ptype in type_list:
        lang_tools = build_tools_map.get(ptype)
        if not lang_tools:
            continue
        if isinstance(lang_tools, list):
            cp = exec_tool(
                "auto-build",
                lang_tools,
                src,
                env=os.environ.copy(),
                stdout=subprocess.PIPE,
            )
            if cp:
                LOG.debug(cp.stdout)
                ret = ret & (cp.returncode == 0)
            if len(type_list) == 1:
                return ret
        # Look for any _scan function in this module for execution
        try:
            dfn = getattr(sys.modules[__name__], "%s_build" % ptype, None)
            if dfn:
                dfn(src, reports_dir, lang_tools)
        except Exception:
            continue
    return ret


def java_build(src, reports_dir, lang_tools):  # scan:ignore
    """
    Automatically build java project

    :param src: Source directory
    :param reports_dir: Reports directory to store any logs
    :param lang_tools: Language specific build tools

    :return: boolean status from the build. True if the command executed successfully. False otherwise
    """
    cmd_args = []
    pom_files = [p.as_posix() for p in Path(src).rglob("pom.xml")]
    gradle_files = [p.as_posix() for p in Path(src).rglob("build.gradle")]
    sbt_files = [p.as_posix() for p in Path(src).rglob("build.sbt")]
    bazel_files = find_files(src, ".bazel", False, True)
    env = get_env()
    if pom_files:
        cmd_args = lang_tools.get("maven")
    elif gradle_files:
        cmd_args = get_gradle_cmd(src, lang_tools.get("gradle"))
    elif sbt_files:
        cmd_args = lang_tools.get("sbt")
    elif bazel_files:
        LOG.info(
            "Build the project using bazel build command and pass the jar path as SHIFTLEFT_ANALYZE_FILE"
        )
        return False
    if not cmd_args:
        LOG.info(
            "Java auto build is supported only for maven or gradle or sbt based projects"
        )
        return False
    cp = exec_tool("auto-build", cmd_args, src, env=env, stdout=subprocess.PIPE)
    if cp:
        LOG.debug(cp.stdout)
        return cp.returncode == 0
    return False


def android_build(src, reports_dir, lang_tools):  # scan:ignore
    """
    Automatically build android project

    :param src: Source directory
    :param reports_dir: Reports directory to store any logs
    :param lang_tools: Language specific build tools

    :return: boolean status from the build. True if the command executed successfully. False otherwise
    """
    if not os.getenv("ANDROID_SDK_ROOT") and not os.getenv("ANDROID_HOME"):
        LOG.info(
            "ANDROID_SDK_ROOT or ANDROID_HOME should be set for automatically building android projects"
        )
        return False
    lang_tools = build_tools_map.get("android")
    env = get_env()
    gradle_files = [p.as_posix() for p in Path(src).rglob("build.gradle")]
    gradle_kts_files = [p.as_posix() for p in Path(src).rglob("build.gradle.kts")]
    bazel_files = find_files(src, ".bazel", False, True)
    if gradle_files or gradle_kts_files:
        cmd_args = get_gradle_cmd(src, lang_tools.get("gradle"))
    elif bazel_files:
        LOG.info(
            "Build the project using bazel build command and pass the jar path as SHIFTLEFT_ANALYZE_FILE"
        )
        return False
    cp = exec_tool("auto-build", cmd_args, src, env=env, stdout=subprocess.PIPE)
    if cp:
        LOG.debug(cp.stdout)
        return cp.returncode == 0
    return False


def kotlin_build(src, reports_dir, lang_tools):  # scan:ignore
    """
    Automatically build kotlin project

    :param src: Source directory
    :param reports_dir: Reports directory to store any logs
    :param lang_tools: Language specific build tools

    :return: boolean status from the build. True if the command executed successfully. False otherwise
    """
    # Check if this is a android kotlin project
    gradle_kts_files = [p.as_posix() for p in Path(src).rglob("build.gradle.kts")]
    if find_files(src, "proguard-rules.pro", False, True) or find_files(
        src, "AndroidManifest.xml", False, True
    ):
        return android_build(src, reports_dir, lang_tools)
    if gradle_kts_files:
        cmd_args = get_gradle_cmd(src, lang_tools.get("gradle"))
        cp = exec_tool(
            "auto-build", cmd_args, src, env=get_env(), stdout=subprocess.PIPE
        )
        if cp:
            LOG.debug(cp.stdout)
            return cp.returncode == 0
    else:
        return java_build(src, reports_dir, lang_tools)


def scala_build(src, reports_dir, lang_tools):  # scan:ignore
    """
    Automatically build scala project

    :param src: Source directory
    :param reports_dir: Reports directory to store any logs
    :param lang_tools: Language specific build tools

    :return: boolean status from the build. True if the command executed successfully. False otherwise
    """
    return java_build(src, reports_dir, lang_tools)


def groovy_build(src, reports_dir, lang_tools):  # scan:ignore
    """
    Automatically build groovy project

    :param src: Source directory
    :param reports_dir: Reports directory to store any logs
    :param lang_tools: Language specific build tools

    :return: boolean status from the build. True if the command executed successfully. False otherwise
    """
    return java_build(src, reports_dir, lang_tools)


def nodejs_build(src, reports_dir, lang_tools):  # scan:ignore
    """
    Automatically build nodejs project

    :param src: Source directory
    :param reports_dir: Reports directory to store any logs
    :param lang_tools: Language specific build tools

    :return: boolean status from the build. True if the command executed successfully. False otherwise
    """
    cmd_args = lang_tools.get("npm")
    yarn_mode = False
    rush_mode = False
    rushjson_files = [p.as_posix() for p in Path(src).glob("rush.json")]
    pjson_files = [p.as_posix() for p in Path(src).glob("package.json")]
    ylock_files = [p.as_posix() for p in Path(src).glob("yarn.lock")]
    if ylock_files:
        cmd_args = lang_tools.get("yarn")
        yarn_mode = True
    elif rushjson_files:
        cmd_args = lang_tools.get("rush")
        rush_mode = True
    elif not pjson_files:
        LOG.debug(
            "Nodejs auto build is supported only for npm or yarn or rush based projects"
        )
        return False
    cp = exec_tool("auto-build", cmd_args, src)
    if cp:
        ret = cp.returncode == 0
    else:
        ret = False
    try:
        cmd_args = ["npm"]
        if yarn_mode:
            cmd_args = ["yarn"]
        if rush_mode:
            cmd_args = ["rush", "rebuild"]
        else:
            cmd_args += ["run", "build"]
        exec_tool("auto-build", cmd_args, src)
    except Exception:
        if rush_mode:
            LOG.warning(
                "Automatic build for rush.js has failed. Try installing the packages manually before invoking scan.\nIf this works then let us know the build steps by filing an issue."
            )
        else:
            LOG.debug("Automatic build has failed for the node.js project")
    return ret


def php_build(src, reports_dir, lang_tools):  # scan:ignore
    """
    Automatically build php project

    :param src: Source directory
    :param reports_dir: Reports directory to store any logs
    :param lang_tools: Language specific build tools

    :return: boolean status from the build. True if the command executed successfully. False otherwise
    """
    ret = False
    cmd_args = lang_tools.get("install")
    cjson_files = [p.as_posix() for p in Path(src).glob("composer.json")]
    # If there is no composer.json try to create one
    if not cjson_files:
        cp = exec_tool(
            "auto-build",
            lang_tools.get("init"),
            src,
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
        )
        if cp:
            LOG.debug(cp.stdout)
    cp = exec_tool(
        "auto-build", cmd_args, src, env=os.environ.copy(), stdout=subprocess.PIPE
    )
    if cp:
        LOG.debug(cp.stdout)
        ret = cp.returncode == 0
    # If composer install fails, try composer update
    if not ret:
        cmd_args = lang_tools.get("update")
        cp = exec_tool(
            "auto-build", cmd_args, src, env=os.environ.copy(), stdout=subprocess.PIPE
        )
        if cp:
            LOG.debug(cp.stdout)
            ret = cp.returncode == 0
    # Do composer autoload now
    if ret:
        cmd_args = lang_tools.get("autoload")
        cp = exec_tool(
            "auto-build", cmd_args, src, env=os.environ.copy(), stdout=subprocess.PIPE
        )
        if cp:
            LOG.debug(cp.stdout)
            ret = cp.returncode == 0
    return ret
