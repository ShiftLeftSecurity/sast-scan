# Introduction

```bash
███████╗██╗  ██╗██╗███████╗████████╗██╗     ███████╗███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║  ██║██║██╔════╝╚══██╔══╝██║     ██╔════╝██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗███████║██║█████╗     ██║   ██║     █████╗  █████╗     ██║       ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔══██║██║██╔══╝     ██║   ██║     ██╔══╝  ██╔══╝     ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║  ██║██║██║        ██║   ███████╗███████╗██║        ██║       ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚══════╝╚══════╝╚═╝        ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

This repo builds `shiftleft/sast-scan`, a container image that powers the ShiftLeft Scan product. Scan products are open-source under a GNU GPL 3.0 or later (GPL-3.0-or-later) license.

## Bundled tools

| Programming Language | Tools                              |
| -------------------- | ---------------------------------- |
| ansible              | ansible-lint                       |
| apex                 | pmd                                |
| aws                  | cfn-lint, cfn_nag                  |
| bash                 | shellcheck                         |
| bom                  | cdxgen                             |
| credscan             | gitleaks                           |
| depscan              | dep-scan                           |
| go                   | gosec, staticcheck                 |
| java                 | cdxgen, gradle, find-sec-bugs, pmd |
| jsp                  | pmd                                |
| json                 | jq, jsondiff, jsonschema           |
| kotlin               | detekt                             |
| kubernetes           | kube-score                         |
| nodejs               | cdxgen, NodeJsScan, eslint, yarn   |
| puppet               | puppet-lint                        |
| plsql                | pmd                                |
| python               | bandit, cdxgen, pipenv             |
| ruby                 | cyclonedx-ruby                     |
| rust                 | cdxgen, cargo-audit                |
| terraform            | tfsec                              |
| Visual Force (vf)    | pmd                                |
| Apache Velocity (vm) | pmd                                |
| yaml                 | yamllint                           |

## Bundled languages/runtime

- jq
- Golang 1.12
- Python 3.6
- OpenJDK 11 (jre)
- Ruby 2.5.5
- Rust
- Node.js 10
- Yarnpkg

## Getting started

sast-scan is ideal for use with CI and also as a pre-commit hook for local development.

### Scanning projects locally

Scan python project

```bash
docker run --rm -e "WORKSPACE=${PWD}" -v $PWD:/app shiftleft/sast-scan scan --src /app --type python
```

Scan multiple projects

```bash
docker run --rm -e "WORKSPACE=${PWD}" -v $PWD:/app shiftleft/sast-scan scan --src /app --type credscan,nodejs,python,yaml --out_dir /app/reports
```

Scan java project

For java and jvm language based projects, it is important to compile the projects before invoking sast-scan in the dev and CI workflow.

```bash
docker run --rm -e "WORKSPACE=${PWD}" -v ~/.m2:/.m2 -v <source path>:/app shiftleft/sast-scan scan --src /app --type java

# For gradle project
docker run --rm -e "WORKSPACE=${PWD}" -v ~/.gradle:/.gradle -v <source path>:/app shiftleft/sast-scan scan --src /app --type java
```

**Automatic project detection**

Feel free to skip `--type` to enable auto-detection. Or pass comma-separated values if the project has multiple types.

### Detailed documentation

Please visit the official [documentation](https://docs.shiftleft.io/shiftleft/scan/scan) site for scan to learn about the configuration and CI/CD integration options.

## Viewing reports

Reports would be produced in the directory specified for `--out_dir`. In the above examples, it is set to `reports` which will be a directory under the source code root directory.

Some of the reports would be converted to a standard called [SARIF](https://sarifweb.azurewebsites.net/). Such reports would end with the extension `.sarif`. To open and view the sarif files require a viewer such as:

- Online viewer - http://sarifviewer.azurewebsites.net/
- VS Code extension - https://marketplace.visualstudio.com/items?itemName=shiftleftsecurity.shiftleft-scan
- Visual Studio extension - https://marketplace.visualstudio.com/items?itemName=WDGIS.MicrosoftSarifViewer
- Azure DevOps extension - https://marketplace.visualstudio.com/items?itemName=shiftleftsecurity.sl-scan-results
