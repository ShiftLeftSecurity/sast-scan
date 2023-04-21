# Introduction

```bash
███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██║     ███████║██╔██╗ ██║
╚════██║██║     ██╔══██║██║╚██╗██║
███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

[Scan](https://appthreat.com) is a free open-source security tool for modern DevOps teams. With an integrated multi-scanner based design, Scan can detect various kinds of security flaws in your application, and infrastructure code in a single fast scan without the need for any _remote server_. Scan is purpose built for workflow integration with nifty features such as automatic build breaker, results baseline and PR summary comments. Scan products are open-source under Apache-2.0 license.

[![Build Status](https://dev.azure.com/shiftleftsecurity/sl-appthreat/_apis/build/status/ShiftLeftSecurity.sast-scan?branchName=master)](https://dev.azure.com/shiftleftsecurity/sl-appthreat/_build/latest?definitionId=11&branchName=master)

## Scan philosophy

- Your code, dependencies, and configuration are your business. No code would ever leave your builds. All scanners, rules and data including the vulnerability database are downloaded locally to perform the scans
- Out-of-the-box experience: Users shouldn't have to configure or learn anything to use scan across languages and pipelines

## Bundled tools

| Programming Language   | Tools                              |
| ---------------------- | ---------------------------------- |
| ansible                | ansible-lint                       |
| apex                   | pmd                                |
| arm                    | checkov                            |
| aws                    | checkov                            |
| bash                   | shellcheck                         |
| bom                    | cdxgen                             |
| credscan               | gitleaks                           |
| depscan                | dep-scan                           |
| dockerfile             | checkov                            |
| go                     | gosec, staticcheck                 |
| groovy                 | find-sec-bugs                      |
| java                   | cdxgen, gradle, find-sec-bugs, pmd |
| jsp                    | pmd, find-sec-bugs                 |
| json                   | jq, jsondiff, jsonschema           |
| kotlin                 | detekt, find-sec-bugs              |
| scala                  | find-sec-bugs                      |
| kubernetes             | checkov, kubesec, kube-score       |
| nodejs                 | cdxgen, yarn, rush                 |
| php                    | psalm, phpstan (ide only)          |
| plsql                  | pmd                                |
| python                 | cfg-scan (1), bandit, cdxgen       |
| ruby                   | brakeman (2), dep-scan             |
| rust                   | cdxgen                             |
| serverless             | checkov                            |
| terraform              | checkov, tfsec                     |
| Visual Force (vf)      | pmd                                |
| Apache Velocity (vm)   | pmd                                |
| yaml                   | yamllint                           |
| docker/container image | dep-scan                           |

- (1) - Deep analyzer for Python is a built-in feature
- (2) - Brakeman is not bundled with scan. Use brakeman with an appropriate license and export the report in json format using `-o reports/source-ruby-report.json`

## Bundled languages/runtime

- jq
- Golang 1.14
- Python 3.8
- OpenJDK 11
- Node.js 10
- Yarnpkg

Please visit the official [documentation](https://appthreat.com) site for scan to learn about the configuration and CI/CD integration options. We also have a dedicated [discord channel](https://discord.gg/DCNxzaeUpd) for issues and support.

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

### Scanning container images

Scanning container images is now possible with slscan. The recommended approach is to export the container image using docker or podman save command first followed by an invocation of scan with the .tar file.

```bash
docker pull shiftleft/scan-slim:latest
docker save -o scanslim.tar shiftleft/scan-slim:latest
# podman save --format oci-archive -o scanslim.tar shiftleft/scan-slim:latest
docker run --rm -e "WORKSPACE=${PWD}" -v $PWD:/app shiftleft/scan scan --src /app/scanslim.tar -o /app/reports --type docker
```

Alternatively, it is possible to let scan pull the container image before analysis. However, it requires exposing your docker or podman daemon socket and therefore **not recommended**. You can try it if you are feeling adventurous by passing the below parameters to the docker run command.

```bash
-e "DOCKER_HOST=unix:/var/run/docker.sock:" -v "/var/run/docker.sock:/var/run/docker.sock"
```

Example: To scan the container image `shiftleft/scan-slim`:

```bash
docker run --rm -e "WORKSPACE=$(pwd)" -e "DOCKER_HOST=unix:/var/run/docker.sock:" \
    -v "/var/run/docker.sock:/var/run/docker.sock" \
    -v "$(pwd):/app" shiftleft/scan scan -t docker -i shiftleft/scan-slim
```

Example: To scan the container image `redmine@sha256:a5c5f8a64a0d9a436a0a6941bc3fb156be0c89996add834fe33b66ebeed2439e`:

```bash
docker run --rm -e "WORKSPACE=$(pwd)" -e "DOCKER_HOST=unix:/var/run/docker.sock:" \
    -v "/var/run/docker.sock:/var/run/docker.sock" \
    -v "$(pwd):/app" shiftleft/scan scan -t docker -i redmine@sha256:a5c5f8a64a0d9a436a0a6941bc3fb156be0c89996add834fe33b66ebeed2439e
```

Same example with podman

```bash
podman run --rm -e "WORKSPACE=$(pwd)" -e "DOCKER_HOST=unix:/run/user/1000/podman/podman.sock:" \
    -v "/run/user/1000:/run/user/1000" \
    -v "$(pwd):/app" shiftleft/scan scan -t docker -i redmine@sha256:a5c5f8a64a0d9a436a0a6941bc3fb156be0c89996add834fe33b66ebeed2439e
```

## Viewing reports

Reports would be produced in the directory specified for `--out_dir`. In the above examples, it is set to `reports` which will be a directory under the source code root directory.

Some of the reports would be converted to a standard called [SARIF](https://sarifweb.azurewebsites.net/). Such reports would end with the extension `.sarif`. Opening and viewing sarif files require a viewer such as:

- Online viewer - http://sarifviewer.azurewebsites.net/
- VS Code extension - https://marketplace.visualstudio.com/items?itemName=shiftleftsecurity.shiftleft-scan
- Visual Studio extension - https://marketplace.visualstudio.com/items?itemName=WDGIS.MicrosoftSarifViewer
- Azure DevOps extension - https://marketplace.visualstudio.com/items?itemName=shiftleftsecurity.sl-scan-results

## Issues with dockerhub?

Many scan images are mirrored to quay.io through the CI pipeline. Simply prefix `quay.io/` to the image name. Below are the mirrors available.

- quay.io/shiftleft/scan (https://quay.io/repository/shiftleft/scan)
- quay.io/shiftleft/scan-java (https://quay.io/repository/shiftleft/scan-java)
- quay.io/shiftleft/scan-oss (https://quay.io/repository/shiftleft/scan-oss)

## Scan users

Scan is used by many organizations and over 1000s of opensource projects. Some notable organizations that use scan are:

- Microsoft
- D2iQ
- McKinsey & Company
- NIO
- Neo Financial
- Accenture
- Wipro
- NCI Agency

Send us a PR for including your organization name here. You can also show your support for scan by using the hashtags #slscan on social media.
