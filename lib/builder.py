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
import subprocess
import sys
from pathlib import Path

from lib.config import build_tools_map
from lib.executor import exec_tool
from lib.logger import LOG


def auto_build(type_list, src, reports_dir):
    """
    Automatically build project identified by type

    :param type_list: Project types
    :param src: Source directory
    :param reports_dir: Reports directory to store any logs

    :return: boolean status from the build. True if the command executed successfully. False otherwise
    """
    ret = True
    for ptype in type_list:
        lang_tools = build_tools_map.get(ptype)
        if not lang_tools:
            continue
        if isinstance(lang_tools, list):
            cp = exec_tool(
                lang_tools, src, env=os.environ.copy(), stdout=subprocess.PIPE
            )
            if cp:
                LOG.debug(cp.stdout)
                ret = ret & (cp.returncode == 0)
        # Look for any _scan function in this module for execution
        try:
            ret = ret & getattr(sys.modules[__name__], "%s_build" % ptype)(
                src, reports_dir, lang_tools
            )
        except Exception:
            LOG.debug("Unable to auto build project of type {}".format(ptype))
    return ret


def java_build(src, reports_dir, lang_tools):
    """
    Automatically build java project

    :param src: Source directory
    :param reports_dir: Reports directory to store any logs
    :param lang_tools: Language specific build tools

    :return: boolean status from the build. True if the command executed successfully. False otherwise
    """
    cmd_args = []
    pom_files = [p.as_posix() for p in Path(src).glob("pom.xml")]
    env = os.environ.copy()
    if os.environ.get("USE_JAVA_8") or os.environ.get("WITH_JAVA_8"):
        env["SCAN_JAVA_HOME"] = os.environ.get("SCAN_JAVA_8_HOME")
    else:
        env["SCAN_JAVA_HOME"] = os.environ.get("SCAN_JAVA_11_HOME")
    if pom_files:
        cmd_args = lang_tools.get("maven")
    else:
        gradle_files = [p.as_posix() for p in Path(src).glob("build.gradle")]
        if gradle_files:
            cmd_args = lang_tools.get("gradle")
    if not cmd_args:
        LOG.info("Java auto build is supported only for maven or gradle based projects")
        return False
    cp = exec_tool(cmd_args, src, env=env, stdout=subprocess.PIPE)
    if cp:
        LOG.debug(cp.stdout)
        return cp.returncode == 0
    return False

def nodejs_build(src, reports_dir, lang_tools):
    """
    Automatically build nodejs project

    :param src: Source directory
    :param reports_dir: Reports directory to store any logs
    :param lang_tools: Language specific build tools

    :return: boolean status from the build. True if the command executed successfully. False otherwise
    """
    cmd_args = lang_tools.get("npm")
    yarn_mode = False
    pjson_files = [p.as_posix() for p in Path(src).glob("package.json")]
    ylock_files = [p.as_posix() for p in Path(src).glob("yarn.lock")]
    if ylock_files:
        cmd_args = lang_tools.get("yarn")
        yarn_mode = True
    elif not pjson_files:
        LOG.debug("Nodejs auto build is supported only for npm or yarn based projects")
        return False
    cp = exec_tool(cmd_args, src)
    if cp:
        LOG.debug(cp.stdout)
        ret = cp.returncode == 0
    else:
        ret = False
    try:
        cmd_args = ["npm"]
        if yarn_mode:
            cmd_args = ["yarn"]
        cmd_args += ["run", "build"]
        exec_tool(cmd_args, src)
    except Exception:
        LOG.debug("Automatic build has failed for the node.js project")
    return ret
