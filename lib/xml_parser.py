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

from defusedxml.ElementTree import parse

from lib.constants import PRIORITY_MAP
from lib.utils import find_path_prefix


def get_report_data(xmlfile, file_path_list=[], working_dir=""):
    """Convert xml file to dict

    :param xmlfile: xml file to parse
    :param file_path_list: Full file path for any manipulation
    :param working_dir: Working directory
    """
    issues = []
    metrics = {}
    file_ref = {}
    file_name_prefix = ""
    if not file_path_list:
        file_path_list = []
    et = parse(xmlfile)
    root = et.getroot()
    # Check if this is a checkstyle xml
    if root.tag.lower() == "checkstyle".lower():
        return parse_checkstyle(root, file_path_list, working_dir)
    for child in root:
        issue = {}
        if child.tag.lower() == "BugInstance".lower():
            issue = child.attrib
            if "priority" in child.attrib:
                priority = child.attrib["priority"]
                if priority in PRIORITY_MAP:
                    issue["issue_severity"] = PRIORITY_MAP.get(priority, priority)
            if "cweid" in child.attrib and child.attrib["cweid"]:
                issue["test_id"] = "CWE-" + child.attrib["cweid"]
            elif "type" in child.attrib and child.attrib["type"]:
                issue["test_id"] = child.attrib["type"]
            for ele in child.iter():
                if ele.tag.lower() == "ShortMessage".lower():
                    issue["title"] = ele.text
                if ele.tag.lower() == "LongMessage".lower():
                    issue["description"] = ele.text
                if ele.tag.lower() == "Message".lower():
                    issue["description"] = issue["description"] + " \n" + ele.text
                if ele.tag.lower() == "SourceLine".lower() and (
                    ele.attrib.get("synthetic") == "true"
                    or ele.attrib.get("primary") == "true"
                ):
                    issue["line"] = ele.attrib["start"]
                    fname = ele.attrib["sourcepath"]
                    if fname in file_ref:
                        fname = file_ref[fname]
                    else:
                        if not file_name_prefix:
                            file_name_prefix = find_path_prefix(working_dir, fname)
                        if file_path_list:
                            # FIXME: This logic is too slow.
                            # Tools like find-sec-bugs are not reliably reporting the full path
                            # so such a lookup is required
                            for tf in file_path_list:
                                if tf.endswith(fname):
                                    file_ref[fname] = tf
                                    fname = tf
                                    break
                        elif file_name_prefix:
                            fname = os.path.join(file_name_prefix, fname)
                    issue["filename"] = fname
            issues.append(issue)
        if child.tag.lower() == "FindBugsSummary".lower():
            metrics = {"summary": child.attrib}

    return issues, metrics


def parse_checkstyle(root, file_path_list, working_dir):
    """Parse checkstyle xml"""
    issues = []
    metrics = {}
    for child in root:
        issue = {}
        if child.tag.lower() == "file":
            issue["filename"] = child.attrib["name"]
        for ele in child.iter():
            if ele.tag.lower() == "error":
                issue["line"] = ele.attrib["line"]
                issue["issue_severity"] = ele.attrib["severity"]
                issue["test_id"] = ele.attrib["source"]
                issue["title"] = ele.attrib["message"]
        issues.append(issue)
    return issues, metrics
