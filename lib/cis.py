from pathlib import Path

import yaml

cis_k8s_file = Path(__file__).parent / "data" / "cis-k8s.yaml"
cis_aws_file = Path(__file__).parent / "data" / "cis-aws.yaml"

cis_rules_dict = {}
if not cis_rules_dict:
    for cf in [cis_k8s_file, cis_aws_file]:
        with open(cf) as fp:
            raw_data = fp.read().split("---")
            for tmp_data in raw_data:
                cdata = yaml.safe_load(tmp_data)
                if not cdata:
                    continue
                for group in cdata.get("groups", []):
                    for check in group.get("checks"):
                        for rule in check.get("scan_rule_ids", []):
                            cis_rules_dict[rule.upper()] = check


def get_cis_rules():
    """
    Return data about all CIS data for Kubernetes
    :return: dict containing all CIS data
    """
    return cis_rules_dict


def get_rule(rule_id):
    return cis_rules_dict.get(str(rule_id).upper())
