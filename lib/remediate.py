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

from lib.pyt.vulnerabilities.rules import rules_message_map


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
        desc = rules_message_map.get(rule_id)
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
    return desc
