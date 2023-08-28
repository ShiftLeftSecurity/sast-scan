# Adapted from bandit/core

import io

import lib.config as config
import lib.constants as constants
from lib.logger import LOG


def get_test_id(data):
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


def normalize_severity(severity):
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


class FileLineGetter:

    def __init__(self, fname, expected_lineno=0):
        """
        FileLineGetter is a generator to get specific lines from a file one by one.
        Lines will be decoded from utf8 ignoring decode errors.

        This is a re-implementation of a previous existing method which used python's linecache module.
        Since linecache is not intended for files other than python files, it was replaced with this and
        behavior derived from available documentation and tests, might not be 100% accurate given that the
        usage was not the intended one and therefore there is no defined behavior for it.
        """
        self.fname = fname
        self.f = None
        self.line = None
        self.expected_lineno = expected_lineno
        self.lineno = 0

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next_line(self, expected_lineno):
        """
        Set the current expectation and return the next line if it exists.

        :param expected_lineno: the line we expect to get
        """
        # Just in case this is not used sequentially, we need to reset the file
        if expected_lineno < self.expected_lineno and self.f is not None:
            self.f.seek(0)

        self.expected_lineno = expected_lineno
        return next(self, None)

    def next(self) -> str:
        """
        Get the next expected line from the file.
        """
        if self.f is None:
            try:
                self.f = io.open(self.fname, "r", encoding='utf8', errors='ignore')
            except UnicodeDecodeError as err:
                LOG.debug(f"Error parsing the file {self.fname} in utf-8. Falling to binary mode")
                self.f = io.open(self.fname, "rb")
            except FileNotFoundError as err:
                LOG.debug(f"Line {self.line} of file {self.fname} was requested but the file was not found")
                raise StopIteration
        while True:
            self.line = self.f.readline()
            if not self.line:
                self.close()
                raise StopIteration
            self.lineno += 1
            if self.lineno - 1 == self.expected_lineno:
                return self.line

    def close(self):
        """
        Close the file if open.
        """
        if self.f is not None:
            self.f.close()


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
        return "Issue: '{}}' from {}:{}: Severity: {} Confidence: " "{} at {}:{}".format(
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

    def get_code(self, max_lines=config.get("CODE_SNIPPET_MAX_LINES"), tabbed=False):
        """Gets lines of code from a file that generated this issue.

        :param max_lines: Max lines of context to return
        :param tabbed: Use tabbing in the output
        :return: strings of code
        """
        if not self.fname:
            return ""
        text_template = "{}\t{}" if tabbed else "{} {}"
        if not self.snippet_based:
            max_lines = max(max_lines, 1)
            lines = []

            # Calculate the boundaries of code lines, the reasoning is a bit unclear given some out of band knowledge
            # such as configuration CODE_SNIPPET_MAX_LINES
            # will be clarified in a future PR
            lmin = max(1, self.lineno - max_lines // 2)
            lmax = lmin + len(self.linerange) + max_lines - 1
            file_liner = FileLineGetter(self.fname, lmin)
            for line in range(lmin, lmax):
                text = file_liner.next_line(line)
                if text is None:
                    break
                if len(text.strip()) == 0:
                    continue
                lines.append(text_template.format(line, text))
            file_liner.close()
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
            return text_template.format(lineno, self.code)

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
        return normalize_severity(severity)

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

    @classmethod
    def from_dict(cls, data, with_code=True):
        """Construct an issue from dictionary of values from the tools

        :param data: Data dictionary from the tools
        :param with_code: Boolean indicating if code snippet should get added
        """
        new_issue = Issue()
        if "code" in data and data.get("code"):
            if str(data["code"]).isdigit():
                new_issue.test_id = str(data["code"])
            elif len(data.get("code").split()) > 1:
                new_issue.code = data["code"]
            else:
                new_issue.test_id = data["code"]
        if "lines" in data:
            new_issue.code = data["lines"]
        if "filename" in data:
            new_issue.fname = data["filename"]
        if "fileName" in data:
            new_issue.fname = data["fileName"]
        if (
                "location" in data
                and data.get("location")
                and "filename" in data["location"]
        ):
            new_issue.fname = data["location"]["filename"]
        if "location" in data and data.get("location") and "file" in data["location"]:
            new_issue.fname = data["location"]["file"]
        if "file" in data:
            new_issue.fname = data["file"]
        if "path" in data:
            new_issue.fname = data["path"]
        if "file_path" in data:
            new_issue.fname = data["file_path"]
        new_issue.severity = new_issue.find_severity(data)
        if "issue_confidence" in data:
            new_issue.confidence = data["issue_confidence"].upper()
        if "confidence" in data:
            new_issue.confidence = data["confidence"].upper()
        if "issue_text" in data:
            new_issue.text = data["issue_text"]
        if "title" in data:
            new_issue.text = data["title"]
        if "warning_type" in data:
            new_issue.test = data["warning_type"]
        if "commitMessage" in data and "commit" in data:
            if data.get("commitMessage") == "***STAGED CHANGES***":
                new_issue.text = "Credential in plaintext?\n\nRule: {}, Secret: {}".format(
                    data.get("rule"), data.get("offender")
                )
            else:
                new_issue.text = "Credential in plaintext?\n\nRule: {}\nLine: {}\n\nCommit: {}".format(
                    data.get("rule", ""),
                    data.get("line"),
                    data.get("commit", ""),
                )
            tmplines = data.get("line", "").split("\n")
            tmplines = [li for li in tmplines if li and li.strip() != ""]
            new_issue.code = tmplines[0]
            if len(tmplines) > 1:
                new_issue.linerange = tmplines
            new_issue.snippet_based = True
        if "details" in data:
            new_issue.text = data["details"]
        if "description" in data:
            new_issue.text = data["description"]
        if "short_description" in data:
            new_issue.short_description = data["short_description"]
        if "cwe_category" in data:
            new_issue.cwe_category = data["cwe_category"]
        if "owasp_category" in data:
            new_issue.owasp_category = data["owasp_category"]
        if "message" in data:
            new_issue.text = data["message"].replace("\\", " \\ ")
        if "test_name" in data:
            new_issue.test = data["test_name"]
        if "title" in data:
            new_issue.test = data["title"]
        if "rule" in data:
            new_issue.test = data["rule"]
        if "check_class" in data:
            tmp_check_class = data["check_class"]
            tmp_check_class = tmp_check_class.split(".")[-1]
            new_issue.test = tmp_check_class
            new_issue.snippet_based = True
        if "type" in data:
            if "message" in data:
                new_issue.test = data["message"].replace("\\", " \\ ")
            else:
                new_issue.test = data["type"]
        if "check_name" in data and "check_id" in data:
            new_issue.text = data["check_name"]
            new_issue.severity = "HIGH"
            new_issue.confidence = "HIGH"
            # Checkov bug workaround for file path
            if new_issue.fname and new_issue.fname.startswith("/"):
                new_issue.fname = new_issue.fname[1:]
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
                    new_issue.code = "\n".join(tmp_code[0:max_code_lines])
        new_issue.test_id = get_test_id(data)
        if "link" in data:
            new_issue.test_ref_url = data["link"]
        if "more_info" in data:
            new_issue.test_ref_url = data["more_info"]
        if "guideline" in data:
            new_issue.test_ref_url = data["guideline"]
        if "line_range" in data:
            new_issue.linerange = data["line_range"]
        if "line_from" in data and "line_to" in data:
            new_issue.linerange = [data["line_from"], data["line_to"]]
        if "file_line_range" in data:
            new_issue.linerange = data["file_line_range"]
        new_issue.lineno = new_issue.get_lineno(data)
        if "first_found" in data:
            new_issue.first_found = data["first_found"]
        if "tags" in data and isinstance(data["tags"], dict):
            new_issue.tags = data["tags"]
        return new_issue
