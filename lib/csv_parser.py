import csv


def get_report_data(csvfile):
    """Convert csv file to dict

    :param csvfile: CSV file to parse
    """
    raw_data = csv.reader(csvfile, delimiter=",")
    report_data = []
    headers = None
    for row in raw_data:
        if not headers:
            headers = [r.lower().replace(" ", "_") for r in row]
        else:
            report_data.append(dict(zip(headers, row)))
    return headers, report_data
