from defusedxml.ElementTree import parse


def get_report_data(xmlfile, file_path_list=[]):
    """Convert xml file to dict

    :param xmlfile: xml file to parse
    :param file_path_list: Full file path for any manipulation
    """
    issues = []
    metrics = {}
    file_ref = {}
    if not file_path_list:
        file_path_list = []
    et = parse(xmlfile)
    root = et.getroot()
    for child in root:
        issue = {}
        if child.tag.lower() == "BugInstance".lower():
            issue = child.attrib
            if "priority" in child.attrib:
                issue["issue_severity"] = child.attrib["priority"]
            if "cweid" in child.attrib and child.attrib["cweid"]:
                issue["test_id"] = "CWE-" + child.attrib["cweid"]
            elif "type" in child.attrib and child.attrib["type"]:
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
                if ele.tag.lower() == "SourceLine".lower() and (
                    ele.attrib.get("synthetic") == "true"
                    or ele.attrib.get("primary") == "true"
                ):
                    issue["line"] = ele.attrib["start"]
                    fname = ele.attrib["sourcepath"]
                    if fname in file_ref:
                        fname = file_ref[fname]
                    else:
                        for tf in file_path_list:
                            if tf.endswith(fname):
                                file_ref[fname] = tf
                                fname = tf
                                break
                    issue["filename"] = fname
            issues.append(issue)
        if child.tag.lower() == "FindBugsSummary".lower():
            metrics = {"summary": child.attrib}

    return issues, metrics
