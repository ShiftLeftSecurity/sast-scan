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

from lib.cis import get_rule
from lib.pyt.vulnerabilities.rules import rules_message_map

IAC_LINKS = "\n\n## Documentation\n\n- [AWS Terraform](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)\n- [Azure Terraform](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)\n- [Google Cloud Terraform](https://registry.terraform.io/providers/hashicorp/google/latest/docs)"


def get_help(
    rule_id, rule_obj=None, tool_name=None, owasp_category=None, cwe_category=None
):
    """
    Method to find remediation text for the given rule, tool and categories

    :param rule_id: Rule id
    :param rule_obj: Rule object from the SARIF file
    :param tool_name: Full name of the tool
    :param owasp_category: OWASP category
    :param cwe_category: CWE category

    :return: Help text in markdown format
    """
    desc = ""
    if rules_message_map.get(rule_id):
        return rules_message_map.get(rule_id)
    cis_rule = get_rule(rule_id)
    if cis_rule:
        cis_desc = cis_rule.get("text", "").strip()
        if cis_desc and not cis_desc.endswith("."):
            cis_desc = cis_desc + "."
        rem_text = cis_rule.get(
            "remediation",
            f"Refer to the provider documentation for the configuration options available.{IAC_LINKS}",
        )
        rationale_text = cis_rule.get("rationale", "")
        if rationale_text:
            rationale_text += "\n"
        desc = f"""CIS Benchmark: **{cis_rule.get("id", "")}**\n\n{cis_desc}\n\n{rationale_text}## Remediation\n\n{rem_text}"""
        if cis_rule.get("help_url"):
            help_urls = "\n- ".join(cis_rule.get("help_url"))
            desc = desc + f"""\n\n## Additional information\n\n- {help_urls}"""
        return desc
    else:
        desc = rule_obj.get("fullDescription", {}).get("text")
        if desc:
            desc = desc.replace("'", "`")
        helpUri = rule_obj.get("helpUri")
        if helpUri and "slscan" not in helpUri:
            desc += "\n\n## Additional information\n\n"
            if rule_obj.get("name"):
                desc += f"""**[{rule_obj.get("name")}]({helpUri})**"""
            else:
                desc += f"**[{rule_id}]({helpUri})**"
        if "CKV_" in rule_id:
            desc += IAC_LINKS
    return desc
