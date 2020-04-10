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

from defusedxml.ElementTree import parse

from lib.constants import PRIORITY_MAP


def get_report_data(xmlfile, file_path_list=[]):
    """Convert xml file to dict

    :param xmlfile: xml file to parse
    :param file_path_list: Full file path for any manipulation
    """
    issues = []
    metrics = {}
    file_ref = {}
    if not file_path_list:
        file_path_list = []
    et = parse(xmlfile)
    root = et.getroot()
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
                        # FIXME: This logic is too slow.
                        # Tools like find-sec-bugs are not reliably reporting the full path
                        # so such a lookup is required
                        for tf in file_path_list:
                            if tf.endswith(fname):
                                file_ref[fname] = tf
                                fname = tf
                                break
                    issue["filename"] = fname
            issues.append(issue)
        if child.tag.lower() == "FindBugsSummary".lower():
            metrics = {"summary": child.attrib}

    return issues, metrics
