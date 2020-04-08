# Introduction

This document describes the output SARIF format emitted by `sast-scan` tool for integration purposes.

## SARIF specification

sast-tool implements version 2.1.0 specification which can be found [here](https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html#_Toc16012479). Every release of sast-tool is carefully tested to remain compliant and produce valid SARIF files. The [online validator](https://sarifweb.azurewebsites.net/Validation) can be used to validate the [sample files](test/data/bandit-report.sarif) attached with this repo.

## SARIF components

### sarifLog

- version: 2.1.0
- \$schema: https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json
- inlineExternalProperties:
  - guid - UUID representing each report from the tool
  - runGuid - UUID representing an invocation of sast-scan which can produce multiple reports. This can be specified by setting the environment variable `SCAN_ID`
- runs: Array with a single run object representing a single run of a tool. This might however change in the future to represent tools that perform multiple scans per invocation.

### run

- tool:
  - driver: This section would describe the tool used to perform the scan along with the rules applied. Eg: A scan for python would lead to the below section

```json
"tool": {
  "driver": {
    "name": "Security audit for python",
    "rules": [
      {
        "id": "B322",
        "name": "blacklist",
        "helpUri": "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html#b322-input"
      }
      ...
    ]
  }
}
```

- conversion: This section would contain information on how sast-scan utilized the underlying tool to perform the report conversion to SARIF format.
- invocations: This section would contain useful information such as:
  - endTimeUtc: Scan end time
  - workingDirectory: Working directory used for the scan
- properties:
  - metrics: This section contains the scan summary such as total issues found as well as the number of critical, high, medium and low issues

```json
"properties": {
  "metrics": {
    "total": 35,
    "critical": 0,
    "high": 5,
    "medium": 30,
    "low": 0
  }
}
```

- results: An array of result object representing the findings

### result

- message: Detailed message from the tool representing the finding
- level: string representing the type of finding - can be error, warning, note
- locations: An array of information representing the source code, line numbers, filename (`artifactLocation`) along with the code snippet highlighting the issue. artifactLocation would start with either https:// or file:// protocol depending on the `WORKSPACE` environment variable used
- properties:
  - issue_confidence: UPPER case flag indicating the confidence level of the tool for the particular result. Valid values are: HIGH, MEDIUM, LOW
  - issue_severity: UPPER case flag indicating the severity level of the particular result. Valid values are: HIGH, MEDIUM, LOW
- ruleId: ID of the rule used. This will be the present in the list of rules mentioned in the tool section
- ruleIndex: Index of the rule in the tool section for faster lookups

Example of a result is shown below:

```json
{
  "message": {
    "text": "The input method in Python 2 will read from standard input, evaluate and run the resulting string as python source code. This is similar, though in many ways worse, then using eval. On Python 2, use raw_input instead, input is safe in Python 3."
  },
  "level": "error",
  "locations": [
    {
      "physicalLocation": {
        "region": {
          "snippet": {
            "text": "        response = input('Enter the hash that follows ' + lastkey + ': ')\n"
          },
          "startLine": 24
        },
        "artifactLocation": {
          "uri": "file:///Users/guest/work/shiftleft/vulpy/utils/skey.py"
        },
        "contextRegion": {
          "snippet": {
            "text": "    while True:\n        response = input('Enter the hash that follows ' + lastkey + ': ')\n        result = hashlib.new(ALGORITHM, response.encode()).hexdigest()\n"
          },
          "endLine": 25,
          "startLine": 23
        }
      }
    }
  ],
  "properties": {
    "issue_confidence": "HIGH",
    "issue_severity": "HIGH"
  },
  "hostedViewerUri": "https://sarifviewer.azurewebsites.net",
  "ruleId": "B322",
  "ruleIndex": 0
}
```
