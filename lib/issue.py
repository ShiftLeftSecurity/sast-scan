# Adapted from bandit/core

import linecache

from six import moves

import lib.constants as constants


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
        }

        if with_code:
            out["code"] = self.get_code()
        return out

    def norm_severity(self, severity):
        """Method to normalize severity and convert non-standard strings

        :param severity: String severity for the issue
        """
        if severity == "ERROR":
            return "CRITICAL"
        if severity == "WARN" or severity == "WARNING":
            return "MEDIUM"
        if severity == "INFO":
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
            self.text = "Commit: {}\nLine: {}\n\nMessage: {}".format(
                data.get("commit", ""), data.get("line"), data.get("commitMessage", "")
            )
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
        if "rule_set" in data:
            self.test_id = data["rule_set"]
        if "test_id" in data:
            self.test_id = data["test_id"]
        if "rule_id" in data:
            self.test_id = data["rule_id"]
        if "link" in data:
            self.test_ref_url = data["link"]
        if "more_info" in data:
            self.test_ref_url = data["more_info"]
        self.lineno = self.get_lineno(data)
        if "line_range" in data:
            self.linerange = data["line_range"]


def issue_from_dict(data):
    i = Issue()
    i.from_dict(data)
    return i
