"""This formatter outputs the issues in JSON."""
import json
from datetime import datetime

from lib.logger import LOG
from lib.pyt.vulnerabilities.vulnerability_helper import (
    SanitisedVulnerability,
    UnknownVulnerability,
)


def report(vulnerabilities, insights, report_fname):
    """
    Prints issues in JSON format.
    Args:
        vulnerabilities: list of vulnerabilities to report
        insights: list of insights
        report_fname: The output file name
    """
    TZ_AGNOSTIC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
    time_string = datetime.utcnow().strftime(TZ_AGNOSTIC_FORMAT)
    filtered_vulns = []
    filtered_insights = []
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
    for ins in insights:
        filtered_insights.append(
            {
                "rule_id": ins.code,
                "rule_name": ins.name,
                "short_description": ins.short_description,
                "description": ins.short_description,
                "recommendation": ins.recommendation,
                "cwe_category": ins.cwe_category,
                "owasp_category": ins.owasp_category,
                "severity": ins.severity,
                "source": {
                    "trigger_word": ins.source.trigger_word,
                    "line_number": ins.source.line_number,
                    "label": ins.source.label,
                    "path": ins.source.path,
                },
                "sink": {
                    "trigger_word": ins.sink.trigger_word,
                    "line_number": ins.sink.line_number,
                    "label": ins.sink.label,
                    "path": ins.sink.path,
                },
            }
        )
    if filtered_insights:
        filtered_vulns += filtered_insights
    machine_output = {"generated_at": time_string, "vulnerabilities": filtered_vulns}
    try:
        with open(report_fname, mode="w") as fileobj:
            json.dump(machine_output, fileobj, indent=2)
    except Exception as e:
        LOG.debug(e)
