# Introduction

```bash
███████╗██╗  ██╗██╗███████╗████████╗██╗     ███████╗███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║  ██║██║██╔════╝╚══██╔══╝██║     ██╔════╝██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗███████║██║█████╗     ██║   ██║     █████╗  █████╗     ██║       ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔══██║██║██╔══╝     ██║   ██║     ██╔══╝  ██╔══╝     ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║  ██║██║██║        ██║   ███████╗███████╗██║        ██║       ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚══════╝╚══════╝╚═╝        ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

This repo builds `shiftleft/sast-scan` (or `gcr.io/sl-appthreat/sast-scan`), a container image that powers the ShiftLeft Scan product.

## Bundled tools

| Programming Language | Tools                            |
| -------------------- | -------------------------------- |
| ansible              | ansible-lint                     |
| aws                  | cfn-lint, cfn_nag                |
| bash                 | shellcheck                       |
| bom                  | cdxgen                           |
| credscan             | gitleaks                         |
| depscan              | dep-scan                         |
| golang               | gosec, staticcheck               |
| java                 | cdxgen, gradle, find-sec-bugs    |
| json                 | jq, jsondiff, jsonschema         |
| kotlin               | detekt                           |
| kubernetes           | kube-score                       |
| nodejs               | cdxgen, NodeJsScan, eslint, yarn |
| puppet               | puppet-lint                      |
| python               | bandit, cdxgen, pipenv           |
| ruby                 | cyclonedx-ruby                   |
| rust                 | cdxgen, cargo-audit              |
| terraform            | tfsec                            |
| yaml                 | yamllint                         |

## Bundled languages/runtime

- jq
- Golang 1.12
- Python 3.6
- OpenJDK 11 (jre)
- Ruby 2.5.5
- Rust
- Node.js 10
- Yarnpkg

Some reports get converted into an open-standard called [SARIF](https://sarifweb.azurewebsites.net/). Please see the section on `Viewing reports` for various viewer options for this.

### Tools enabled for SARIF conversion

- Bash - shellcheck
- Credscan - gitleaks
- Python - bandit
- Node.js - NodeJsScan
- Java - pmd, find-sec-bugs
- Golang - gosec, staticcheck
- Terraform - tfsec

## Usage

sast-scan is ideal for use with CI and also as a pre-commit hook for local development.

## Integration with Azure DevOps

Refer to the [document](docs/azure-devops.md)

## Integration with GitHub action

This tool can be used with GitHub actions using this [action](https://github.com/marketplace/actions/sast-scan). All the supported languages can be used.

This repo self-tests itself with sast-scan! Check the GitHub [workflow file](https://github.com/ShiftLeftSecurity/sast-scan/blob/master/.github/workflows/pythonapp.yml) of this repo.

```yaml
- name: Self sast-scan
  uses: AppThreat/sast-scan-action@v1.0.0
  with:
    output: reports
    type: python,bash
- name: Upload scan reports
  uses: actions/upload-artifact@v1.0.0
  with:
    name: sast-scan-reports
    path: reports
```

## Integration with Google CloudBuild

Use this [custom builder](https://github.com/CloudBuildr/google-custom-builders/tree/master/sast-scan) to add sast-scan as a build step.

The full steps are reproduced below.

1. Add the custom builder to your project

```bash
git clone https://github.com/CloudBuildr/google-custom-builders.git
cd google-custom-builders/sast-scan
gcloud builds submit --config cloudbuild.yaml .
```

2. Use it in cloudbuild.yaml

```yaml
steps:
  - name: "gcr.io/$PROJECT_ID/sast-scan"
    args: ["--type", "python"]
```

## Integration with CircleCI

Refer to the [document](docs/circleci.md)

## Custom integration

SARIF reports produced by sast-scan can be integrated with other compatible tools. It can also be easily imported into databases such as BigQuery for visualization purposes. Refer to [integration](docs/integration.md) document for detailed explanation on the SARIF format.

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

### Invoking built-in tools

Bandit

```bash
docker run --rm -v <source path>:/app shiftleft/sast-scan bandit -r /app
```

## Viewing reports

Reports would be produced in the directory specified for `--out_dir`. In the above examples, it is set to `reports` which will be a directory under the source code root directory.

Some of the reports would be converted to a standard called [SARIF](https://sarifweb.azurewebsites.net/). Such reports would end with the extension `.sarif`. To open and view the sarif files require a viewer such as:

- Online viewer - http://sarifviewer.azurewebsites.net/
- VS Code extension - https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer
- Visual Studio extension - https://marketplace.visualstudio.com/items?itemName=WDGIS.MicrosoftSarifViewer
- Azure DevOps extension - <ShiftLeft Scan Reports url here>

**Example reports:**

Online viewer can be used to manually upload the .sarif files as shown.

![Online viewer](docs/sarif-online-viewer.png)

Azure DevOps SARIF plugin can be integrated to show the analysis integrated with the build run as shown.

![Azure DevOps integration](docs/azure-devops.png)

![Build breaker](docs/build-breaker.png)
