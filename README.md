# Introduction

```bash
███████╗██╗  ██╗██╗███████╗████████╗██╗     ███████╗███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║  ██║██║██╔════╝╚══██╔══╝██║     ██╔════╝██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗███████║██║█████╗     ██║   ██║     █████╗  █████╗     ██║       ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔══██║██║██╔══╝     ██║   ██║     ██╔══╝  ██╔══╝     ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║  ██║██║██║        ██║   ███████╗███████╗██║        ██║       ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚══════╝╚══════╝╚═╝        ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

ShiftLeft Scan is a free open-source security tool for modern DevOps teams. With an integrated multi-scanner based design, ShiftLeft Scan can detect various kinds of security flaws in your application and infrastructure code in a single fast scan. Scan products are open-source under a GNU GPL 3.0 or later (GPL-3.0-or-later) license.

[![Build Status](https://dev.azure.com/shiftleftsecurity/sl-appthreat/_apis/build/status/ShiftLeftSecurity.sast-scan?branchName=master)](https://dev.azure.com/shiftleftsecurity/sl-appthreat/_build/latest?definitionId=11&branchName=master)

## Bundled tools

| Programming Language | Tools                               |
| -------------------- | ----------------------------------- |
| ansible              | ansible-lint                        |
| apex                 | pmd                                 |
| aws                  | checkov                             |
| bash                 | shellcheck                          |
| bom                  | cdxgen                              |
| credscan             | gitleaks                            |
| depscan              | dep-scan                            |
| go                   | gosec, staticcheck                  |
| groovy               | find-sec-bugs                       |
| java                 | cdxgen, gradle, find-sec-bugs, pmd  |
| jsp                  | pmd, find-sec-bugs                  |
| json                 | jq, jsondiff, jsonschema            |
| kotlin               | detekt, find-sec-bugs               |
| scala                | find-sec-bugs                       |
| kubernetes           | checkov, kubesec, kube-score        |
| nodejs               | cdxgen, njsscan, eslint, yarn, rush |
| php                  | psalm, phpstan (ide only)           |
| plsql                | pmd                                 |
| python               | bandit, cdxgen, pipenv              |
| ruby                 | dep-scan                            |
| rust                 | cdxgen                              |
| terraform            | checkov, tfsec                      |
| Visual Force (vf)    | pmd                                 |
| Apache Velocity (vm) | pmd                                 |
| yaml                 | yamllint                            |

## Bundled languages/runtime

- jq
- Golang 1.14
- Python 3.8
- OpenJDK 11
- Node.js 10
- Yarnpkg

Please visit the official [documentation](https://slscan.io) site for scan to learn about the configuration and CI/CD integration options.

## Getting started

scan is ideal for use with CI and also as a pre-commit hook for local development. Scan is distributed as a container image `shiftleft/scan`, and as an AppImage for supported Linux distributions.

### Scanning projects locally

Easy one-liner command below:

```bash
sh <(curl https://slscan.sh)
```

The above command simply invokes the below docker run command.

```bash
docker run --rm -e "WORKSPACE=${PWD}" -v $PWD:/app shiftleft/scan scan --build
```

On Windows, the command changes slightly depending on the terminal.

cmd

```
docker run --rm -e "WORKSPACE=%cd%" -e "GITHUB_TOKEN=%GITHUB_TOKEN%" -v "%cd%:/app:cached" shiftleft/scan scan
```

PowerShell and PowerShell Core

```
docker run --rm -e "WORKSPACE=$(pwd)" -e "GITHUB_TOKEN=$env:GITHUB_TOKEN" -v "$(pwd):/app:cached" shiftleft/scan scan
```

WSL Bash

```
docker run --rm -e "WORKSPACE=${PWD}" -e "GITHUB_TOKEN=${GITHUB_TOKEN}" -v "$PWD:/app:cached" shiftleft/scan scan
```

git-bash

```
docker run --rm -e "WORKSPACE=${PWD}" -e "GITHUB_TOKEN=${GITHUB_TOKEN}" -v "/$PWD:/app:cached" shiftleft/scan scan
```

Don't forget the slash (/) before \$PWD for git-bash!

Scan multiple projects

```bash
docker run --rm -e "WORKSPACE=${PWD}" -v $PWD:/app shiftleft/scan scan --src /app --type credscan,nodejs,python,yaml --out_dir /app/reports
```

Scan Java project

For Java and JVM language-based projects, it is important to compile the projects before invoking sast-scan in the dev and CI workflow.

```bash
docker run --rm -e "WORKSPACE=${PWD}" -v ~/.m2:/.m2 -v <source path>:/app shiftleft/scan scan --src /app --type java

# For gradle project
docker run --rm -e "WORKSPACE=${PWD}" -v ~/.gradle:/.gradle -v <source path>:/app shiftleft/scan scan --src /app --type java
```

**Automatic project detection**

Feel free to skip `--type` to enable auto-detection. Or pass comma-separated values if the project has multiple types.

## Viewing reports

Reports would be produced in the directory specified for `--out_dir`. In the above examples, it is set to `reports` which will be a directory under the source code root directory.

Some of the reports would be converted to a standard called [SARIF](https://sarifweb.azurewebsites.net/). Such reports would end with the extension `.sarif`. Opening and viewing sarif files require a viewer such as:

- Online viewer - http://sarifviewer.azurewebsites.net/
- VS Code extension - https://marketplace.visualstudio.com/items?itemName=shiftleftsecurity.shiftleft-scan
- Visual Studio extension - https://marketplace.visualstudio.com/items?itemName=WDGIS.MicrosoftSarifViewer
- Azure DevOps extension - https://marketplace.visualstudio.com/items?itemName=shiftleftsecurity.sl-scan-results

## Alternative container images

Scan offers certain language specific container images with additional runtime versions and tools.

| Image name            | Comments                                                         |
| --------------------- | ---------------------------------------------------------------- |
| shiftleft/scan-oss    | Just the OSS tools without any ShiftLeft cli                     |
| shiftleft/scan-java   | Includes both Java 8 and 11 along with ShiftLeft cli             |
| shiftleft/scan-csharp | Includes both .Net core 2.1 and 3.1 SDK along with ShiftLeft cli |

For all other languages, continue to use `shiftleft/sast-scan` or `shiftleft/scan`

## Scan users

Scan is used by many organizations and over 1000s of opensource projects. Some notable organizations that use scan are:

- ShiftLeft
- Microsoft
- D2iQ
- McKinsey & Company
- NIO
- Neo Financial
- Accenture
- Wipro
- NCI Agency

Send us a PR for including your organization name here. You can also show your support for scan by using the hashtags #shiftleft #scan on social media.
