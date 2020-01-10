from defusedxml.ElementTree import parse


def get_report_data(xmlfile):
    """Convert xml file to dict

    :param xmlfile: xml file to parse
    """
    issues = []
    metrics = {}
    et = parse(xmlfile)
    root = et.getroot()
    for child in root:
        issue = {}
        if child.tag.lower() == "BugInstance".lower():
            issue = child.attrib
            if "priority" in child.attrib:
                issue["issue_severity"] = child.attrib["priority"]
            if "type" in child.attrib and child.attrib["type"]:
                issue["test_id"] = child.attrib["type"]
            for ele in child.iter():
                if ele.tag.lower() == "ShortMessage".lower():
                    issue["title"] = ele.text
                if ele.tag.lower() == "LongMessage".lower():
                    issue["description"] = ele.text
                if ele.tag.lower() == "Message".lower():
                    issue["description"] = (
                        issue["description"] + " \n" + ele.text
                    )
                if (
                    ele.tag.lower() == "SourceLine".lower()
                    and "synthetic" in ele.attrib
                    and ele.attrib["synthetic"] == "true"
                ):
                    issue["line"] = ele.attrib["start"]
                    issue["filename"] = ele.attrib["sourcepath"]
            issues.append(issue)
        if child.tag.lower() == "FindBugsSummary".lower():
            metrics = {"summary": child.attrib}

    return issues, metrics
