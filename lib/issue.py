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

# Adapted from bandit/core

import linecache

from six import moves

import lib.constants as constants
from lib.logger import LOG


class Issue(object):
    def __init__(
        self,
        severity=constants.SEVERITY_DEFAULT,
        confidence=constants.CONFIDENCE_DEFAULT,
        text="",
        ident=None,
        lineno=None,
        test_id="",
    ):
        self.severity = severity
        self.confidence = confidence
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        self.text = text
        self.code = ""
        self.ident = ident
        self.fname = ""
        self.test = ""
        self.test_id = test_id
        self.test_ref_url = None
        self.lineno = lineno
        self.linerange = []
        # Does the tool operate in snippet mode. Eg: gitleaks
        self.snippet_based = False
        self.line_hash = ""
        self.first_found = None

    def __str__(self):
        return ("Issue: '%s' from %s:%s: Severity: %s Confidence: " "%s at %s:%i") % (
            self.text,
            self.test_id,
            (self.ident or self.test),
            self.severity,
            self.confidence,
            self.fname,
            self.lineno,
        )

    def __eq__(self, other):
        # if the issue text, severity, confidence, and filename match, it's
        # the same issue from our perspective
        match_types = [
            "text",
            "severity",
            "confidence",
            "fname",
            "test",
            "test_id",
            "line_hash",
        ]
        return all(
            getattr(self, field) == getattr(other, field) for field in match_types
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return id(self)

    def filter(self, severity, confidence):
        """Utility to filter on confidence and severity

        This function determines whether an issue should be included by
        comparing the severity and confidence rating of the issue to minimum
        thresholds specified in 'severity' and 'confidence' respectively.

        Formatters should call manager.filter_results() directly.

        This will return false if either the confidence or severity of the
        issue are lower than the given threshold values.

        :param severity: Severity threshold
        :param confidence: Confidence threshold
        :return: True/False depending on whether issue meets threshold

        """
        rank = constants.RANKING
        return rank.index(self.severity) >= rank.index(severity) and rank.index(
            self.confidence
        ) >= rank.index(confidence)

    def get_code(self, max_lines=3, tabbed=False):
        """Gets lines of code from a file the generated this issue.

        :param max_lines: Max lines of context to return
        :param tabbed: Use tabbing in the output
        :return: strings of code
        """
        if not self.fname:
            return ""
        lines = []
        max_lines = max(max_lines, 1)
        if not self.snippet_based:
            lmin = max(1, self.lineno - max_lines // 2)
            lmax = lmin + len(self.linerange) + max_lines - 1

            tmplt = "%i\t%s" if tabbed else "%i %s"
            for line in moves.xrange(lmin, lmax):
                text = linecache.getline(self.fname, line)

                if isinstance(text, bytes):
                    text = text.decode("utf-8")

                if not len(text):
                    break
                lines.append(tmplt % (line, text))
            return "".join(lines)
        else:
            lineno = self.lineno
            try:
                tmplineno = 1
                with open(self.fname, mode="r") as fp:
                    for aline in fp:
                        if aline.strip() == self.code.strip():
                            lineno = tmplineno
                            # Fix the line number
                            self.lineno = lineno
                            break
                        tmplineno = tmplineno + 1
            except Exception as e:
                LOG.debug(e)
            tmplt = "%i\t%s" if tabbed else "%i %s"
            return tmplt % (lineno, self.code)

    def as_dict(self, with_code=True):
        """Convert the issue to a dict of values for outputting."""
        issue_text = self.text.encode("utf-8").decode("utf-8")
        # As per the spec text sentence should end with a period
        if not issue_text.endswith("."):
            issue_text = issue_text + "."
        out = {
            "filename": self.fname,
            "test_name": self.test,
            "test_id": str(self.test_id),
            "test_ref_url": self.test_ref_url,
            "issue_severity": self.severity,
            "issue_confidence": self.confidence,
            "issue_text": issue_text,
            "line_number": self.lineno,
            "line_range": self.linerange,
            "first_found": self.first_found,
        }

        if with_code:
            out["code"] = self.get_code()
            # If the line number has changed since referring to the file
            # use the latest line number
            if self.lineno != out["line_number"]:
                out["line_number"] = self.lineno
        return out

    def norm_severity(self, severity):
        """Method to normalize severity and convert non-standard strings

        :param severity: String severity for the issue
        """
        if severity == "ERROR" or severity == "SEVERITY_HIGH_IMPACT":
            return "CRITICAL"
        if (
            severity == "WARN"
            or severity == "WARNING"
            or severity == "SEVERITY_MEDIUM_IMPACT"
        ):
            return "MEDIUM"
        if severity == "INFO" or severity == "SEVERITY_LOW_IMPACT":
            return "LOW"
        return severity.upper()

    def find_severity(self, data):
        severity = constants.SEVERITY_DEFAULT
        if "issue_severity" in data or "priority" in data:
            sev = data.get("issue_severity", data.get("priority"))
            severity = sev
            if isinstance(sev, int) or sev.isdigit():
                sev = int(sev)
                if sev <= 3:
                    severity = "LOW"
                elif sev <= 5:
                    severity = "MEDIUM"
                elif sev <= 8:
                    severity = "HIGH"
                elif sev > 8:
                    severity = "CRITICAL"
        if "severity" in data:
            severity = str(data["severity"]).upper()
        if "commit" in data:
            severity = "HIGH"
        return self.norm_severity(severity)

    def get_lineno(self, data):
        """Extract line number with any int conversion"""
        lineno = 1
        tmp_no = 1
        if "line_number" in data:
            tmp_no = data["line_number"]
        elif "line" in data:
            tmp_no = data["line"]
        elif "location" in data and "start_line" in data["location"]:
            tmp_no = data["location"]["start_line"]
        elif "location" in data and "line" in data["location"]:
            tmp_no = data["location"]["line"]
        if str(tmp_no).isdigit():
            lineno = int(tmp_no)
        return lineno

    def get_test_id(self, data):
        """
        Method to retrieve test_id
        :param data:
        :return:
        """
        test_id = ""
        if "rule_set" in data:
            test_id = data["rule_set"]
        if "test_id" in data:
            test_id = data["test_id"]
        if "rule_id" in data:
            test_id = data["rule_id"]
        if "cwe" in data:
            cwe_obj = data["cwe"]
            if isinstance(cwe_obj, str):
                test_id = cwe_obj
            if isinstance(cwe_obj, dict):
                test_id = cwe_obj.get("ID", cwe_obj.get("id", ""))
            if not test_id.startswith("CWE") and test_id.isdigit():
                test_id = "CWE-" + test_id
        if "code" in data:
            if str(data.get("code", "")).isdigit():
                test_id = str(data["code"])
            elif len(data.get("code", "").split()) == 1:
                test_id = data["code"]
        return test_id

    def from_dict(self, data, with_code=True):
        """Construct an issue from dictionary of values from the tools

        :param data: Data dictionary from the tools
        :param with_code: Boolean indicating if code snippet should get added
        """
        if "code" in data:
            if str(data["code"]).isdigit():
                self.test_id = str(data["code"])
            elif len(data.get("code").split()) > 1:
                self.code = data["code"]
            else:
                self.test_id = data["code"]
        if "lines" in data:
            self.code = data["lines"]
        if "filename" in data:
            self.fname = data["filename"]
        if "fileName" in data:
            self.fname = data["fileName"]
        if "location" in data and "filename" in data["location"]:
            self.fname = data["location"]["filename"]
        if "location" in data and "file" in data["location"]:
            self.fname = data["location"]["file"]
        if "file" in data:
            self.fname = data["file"]
        if "path" in data:
            self.fname = data["path"]
        self.severity = self.find_severity(data)
        if "issue_confidence" in data:
            self.confidence = data["issue_confidence"]
        if "confidence" in data:
            self.confidence = data["confidence"]
        if "issue_text" in data:
            self.text = data["issue_text"]
        if "title" in data:
            self.text = data["title"]
        if "commitMessage" in data and "commit" in data:
            if data.get("commitMessage") == "***STAGED CHANGES***":
                self.text = "Credential in plaintext?\n\nRule: {}, Secret: {}".format(
                    data.get("rule"), data.get("offender")
                )
            else:
                self.text = "Credential in plaintext?\n\nRule: {}\nLine: {}\n\nCommit: {}".format(
                    data.get("rule", ""), data.get("line"), data.get("commit", ""),
                )
            tmplines = data.get("line", "").split("\n")
            tmplines = [l for l in tmplines if l and l.strip() != ""]
            self.code = tmplines[0]
            if len(tmplines) > 1:
                self.linerange = tmplines
            self.snippet_based = True
        if "details" in data:
            self.text = data["details"]
        if "description" in data:
            self.text = data["description"]
        if "message" in data:
            self.text = data["message"]
        if "test_name" in data:
            self.test = data["test_name"]
        if "title" in data:
            self.test = data["title"]
        if "rule" in data:
            self.test = data["rule"]
        self.test_id = self.get_test_id(data)
        if "link" in data:
            self.test_ref_url = data["link"]
        if "more_info" in data:
            self.test_ref_url = data["more_info"]
        self.lineno = self.get_lineno(data)
        if "line_range" in data:
            self.linerange = data["line_range"]
        if "first_found" in data:
            self.first_found = data["first_found"]


def issue_from_dict(data):
    i = Issue()
    i.from_dict(data)
    return i
