"""This formatter outputs the issues in JSON."""
import json
from datetime import datetime

from lib.pyt.vulnerabilities.vulnerability_helper import (
    SanitisedVulnerability,
    UnknownVulnerability,
)


def report(
    vulnerabilities, report_fname, print_sanitised,
):
    """
    Prints issues in JSON format.
    Args:
        vulnerabilities: list of vulnerabilities to report
        report_fname: The output file name
    """
    TZ_AGNOSTIC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
    time_string = datetime.utcnow().strftime(TZ_AGNOSTIC_FORMAT)
    filtered_vulns = []
    vuln_keys = {}
    for vuln in vulnerabilities:
        if not isinstance(vuln, SanitisedVulnerability) and not isinstance(
            vuln, UnknownVulnerability
        ):
            avuln = vuln.as_dict()
            avuln_key = f"""{avuln["rule_id"]}|{avuln["source"]["line_number"]}|{avuln["source"]["path"]}|{avuln["sink"]["line_number"]}|{avuln["sink"]["path"]}"""
            if not vuln_keys.get(avuln_key):
                filtered_vulns.append(avuln)
                vuln_keys[avuln_key] = True
    machine_output = {
        "generated_at": time_string,
        "vulnerabilities": filtered_vulns,
    }
    with open(report_fname, mode="w") as fileobj:
        json.dump(machine_output, fileobj, indent=2)
