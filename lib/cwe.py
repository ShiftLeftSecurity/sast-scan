import csv
from pathlib import Path

cwe_software_csv = Path(__file__).parent / "data" / "cwe_software.csv"
cwe_research_csv = Path(__file__).parent / "data" / "cwe_research.csv"

cwe_dict = {}

if not cwe_dict:
    with open(cwe_software_csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cwe_dict[row["CWE-ID"]] = row
    with open(cwe_research_csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cwe_dict[row["CWE-ID"]] = row


def get_all():
    """
    Return data about all CWE
    :return: dict containing all CWE data
    """
    return cwe_dict


def get(cid):
    """
    Return CWE details for the given id
    :param cid: CWE id
    :return: CWE data
    """
    cid = cid.upper().replace("CWE-", "")
    return cwe_dict.get(cid)


def get_name(cid):
    """
    Return the name for the given cwe

    :param cid: cwe id
    :return: Name
    """
    data = get(cid)
    if not data:
        return ""
    name = data.get("Name")
    if not name.endswith("."):
        name = name + "."
    return name


def get_description(cid, extended=False):
    """
    Method to retrieve just the description for the given cwe
    :param cid: cwe id
    :param extended Boolean to indicate if extended description is required
    :return: Description string
    """
    data = get(cid)
    if not data:
        return ""
    desc = data.get("Description")
    if not extended:
        return desc
    if data.get("Extended Description"):
        desc = desc + "\n" + data.get("Extended Description")
    desc = desc.replace("::TYPE:Relationship:NOTE:", "\n\nNOTE:\n")
    desc = desc.replace("::TYPE:Terminology:NOTE:", "\n\nNOTE:\n")
    desc = desc.replace("::", "")
    if not desc.endswith("."):
        desc = desc + "."
    return desc
