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

import io
import linecache

from six import moves

import lib.config as config
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
            text = text.decode("utf-8", "ignore")
        self.text = text
        self.short_description = ""
        self.cwe_category = ""
        self.owasp_category = ""
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
        self.tags = {}

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

    def _get_code_line(self, fname, line):
        """Return the given line from the file. Handles any utf8 error from tokenize

        :param fname: File name
        :param line: Line number
        :return: Exact line as string
        """
        text = ""
        try:
            text = linecache.getline(fname, line)
        except UnicodeDecodeError:
            LOG.debug(
                f"Error parsing the file {fname} in utf-8. Falling to binary mode"
            )
            with io.open(fname, "rb") as fp:
                all_lines = fp.readlines()
                if line < len(all_lines):
                    text = all_lines[line]
        return text

    def get_code(self, max_lines=config.get("CODE_SNIPPET_MAX_LINES"), tabbed=False):
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
                text = self._get_code_line(self.fname, line)
                if isinstance(text, bytes):
                    text = text.decode("utf-8", "ignore")

                if not len(text):
                    break
                lines.append(tmplt % (line, text))
            if lines:
                return "".join(lines)
            elif self.code:
                # Validate if the code snippet is in the right format
                orig_lines = self.code.split("\n")
                if orig_lines:
                    orig_first_line = orig_lines[0]
                    firstword = orig_first_line.split(" ", 1)[0]
                    if firstword and str(firstword).isdigit():
                        return self.code
                return ""
            else:
                return ""
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
        if self.test:
            # Cleanup test names
            if self.test == "blacklist":
                self.test = "blocklist"
            if self.test == "whitelist":
                self.test = "allowlist"
            if "_" in self.test:
                self.test = self.test.replace("_", " ")
                # Title case small rule names
                tmpA = self.test.split(" ")
                if len(tmpA) < 3:
                    self.test = self.test.title()
        if self.test_id:
            override_sev = config.rules_severity.get(str(self.test_id).upper())
            if override_sev:
                self.severity = override_sev
            # Attempt to convert the test_id to cwe id
            if config.CWEMAP.get(self.test_id):
                cwe_id = config.CWEMAP.get(self.test_id)
                if cwe_id:
                    self.test_id = f"CWE-{cwe_id}"
                    self.test_ref_url = config.Cwe(id=cwe_id).link()
        # Take the first line as short description
        if not self.short_description and issue_text:
            self.short_description = issue_text.split(". ")[0]
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
            "short_description": self.short_description,
            "cwe_category": self.cwe_category,
            "owasp_category": self.owasp_category,
            "tags": self.tags,
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
        severity = severity.upper()
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
        return severity

    def find_severity(self, data):
        severity = constants.SEVERITY_DEFAULT
        if "confidence" in data:
            severity = data["confidence"].upper()
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
        elif self.linerange:
            tmp_no = self.linerange[0]
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
        if "check_name" in data:
            test_id = data["check_name"]
        if "check_id" in data:
            test_id = data["check_id"]
        if "tag" in data:
            test_id = data["tag"]
        if "commitMessage" in data and "commit" in data:
            test_id = "CWE-312"
        if "type" in data:
            test_id = data["type"]
        if "cwe" in data:
            cwe_obj = data["cwe"]
            if isinstance(cwe_obj, str):
                test_id = cwe_obj
            if isinstance(cwe_obj, dict):
                tmp_id = cwe_obj.get("ID")
                if not tmp_id:
                    tmp_id = cwe_obj.get("id")
                if tmp_id:
                    test_id = tmp_id
            if not test_id.startswith("CWE") and test_id.isdigit():
                test_id = "CWE-" + test_id
        if not test_id and "code" in data and data.get("code"):
            if str(data.get("code")).isdigit():
                test_id = str(data["code"])
            elif len(data.get("code").split()) == 1:
                test_id = data.get("code")
        return test_id

    def from_dict(self, data, with_code=True):
        """Construct an issue from dictionary of values from the tools

        :param data: Data dictionary from the tools
        :param with_code: Boolean indicating if code snippet should get added
        """
        if "code" in data and data.get("code"):
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
        if (
            "location" in data
            and data.get("location")
            and "filename" in data["location"]
        ):
            self.fname = data["location"]["filename"]
        if "location" in data and data.get("location") and "file" in data["location"]:
            self.fname = data["location"]["file"]
        if "file" in data:
            self.fname = data["file"]
        if "path" in data:
            self.fname = data["path"]
        if "file_path" in data:
            self.fname = data["file_path"]
        self.severity = self.find_severity(data)
        if "issue_confidence" in data:
            self.confidence = data["issue_confidence"].upper()
        if "confidence" in data:
            self.confidence = data["confidence"].upper()
        if "issue_text" in data:
            self.text = data["issue_text"]
        if "title" in data:
            self.text = data["title"]
        if "warning_type" in data:
            self.test = data["warning_type"]
        if "commitMessage" in data and "commit" in data:
            if data.get("commitMessage") == "***STAGED CHANGES***":
                self.text = "Credential in plaintext?\n\nRule: {}, Secret: {}".format(
                    data.get("rule"), data.get("offender")
                )
            else:
                self.text = "Credential in plaintext?\n\nRule: {}\nLine: {}\n\nCommit: {}".format(
                    data.get("rule", ""),
                    data.get("line"),
                    data.get("commit", ""),
                )
            tmplines = data.get("line", "").split("\n")
            tmplines = [li for li in tmplines if li and li.strip() != ""]
            self.code = tmplines[0]
            if len(tmplines) > 1:
                self.linerange = tmplines
            self.snippet_based = True
        if "details" in data:
            self.text = data["details"]
        if "description" in data:
            self.text = data["description"]
        if "short_description" in data:
            self.short_description = data["short_description"]
        if "cwe_category" in data:
            self.cwe_category = data["cwe_category"]
        if "owasp_category" in data:
            self.owasp_category = data["owasp_category"]
        if "message" in data:
            self.text = data["message"].replace("\\", " \\ ")
        if "test_name" in data:
            self.test = data["test_name"]
        if "title" in data:
            self.test = data["title"]
        if "rule" in data:
            self.test = data["rule"]
        if "check_class" in data:
            tmp_check_class = data["check_class"]
            tmp_check_class = tmp_check_class.split(".")[-1]
            self.test = tmp_check_class
            self.snippet_based = True
        if "type" in data:
            if "message" in data:
                self.test = data["message"].replace("\\", " \\ ")
            else:
                self.test = data["type"]
        if "check_name" in data and "check_id" in data:
            self.text = data["check_name"]
            self.severity = "HIGH"
            self.confidence = "HIGH"
            # Checkov bug workaround for file path
            if self.fname and self.fname.startswith("/"):
                self.fname = self.fname[1:]
            if (
                "code_block" in data
                and data["code_block"]
                and isinstance(data["code_block"], list)
            ):
                tmp_code = []
                for lc in data["code_block"]:
                    if isinstance(lc, list):
                        if len(lc) == 2:
                            line_str = "{} {}".format(lc[0], lc[1])
                        else:
                            line_str = lc[0]
                    else:
                        line_str = lc
                    tmp_code.append(line_str)
                max_code_lines = min(
                    len(tmp_code), config.get("CODE_SNIPPET_MAX_LINES")
                )
                if max_code_lines:
                    self.code = "\n".join(tmp_code[0:max_code_lines])
        self.test_id = self.get_test_id(data)
        if "link" in data:
            self.test_ref_url = data["link"]
        if "more_info" in data:
            self.test_ref_url = data["more_info"]
        if "guideline" in data:
            self.test_ref_url = data["guideline"]
        if "line_range" in data:
            self.linerange = data["line_range"]
        if "line_from" in data and "line_to" in data:
            self.linerange = [data["line_from"], data["line_to"]]
        if "file_line_range" in data:
            self.linerange = data["file_line_range"]
        self.lineno = self.get_lineno(data)
        if "first_found" in data:
            self.first_found = data["first_found"]
        if "tags" in data and isinstance(data["tags"], dict):
            self.tags = data["tags"]


def issue_from_dict(data):
    i = Issue()
    i.from_dict(data)
    return i
