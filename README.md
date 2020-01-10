# Introduction

This repo builds `appthreat/sast-scan` (and `quay.io/appthreat/sast-scan`), a container image with a number of bundled open-source static analysis security testing (SAST) tools. This is like a Swiss Army knife for DevSecOps engineers.

Some reports get converted into an open-standard called [SARIF](https://sarifweb.azurewebsites.net/). Please see the section on `Viewing reports` for various viewer options for this.

RedHat's `ubi8/ubi-minimal` is used as a base image instead of the usual alpine to help with enterprise adoption of this tool.

[![Docker Repository on Quay](https://quay.io/repository/appthreat/sast-scan/status "Docker Repository on Quay")](https://quay.io/repository/appthreat/sast-scan)

## Bundled tools

| Programming Language | Tools                                                |
| -------------------- | ---------------------------------------------------- |
| ansible              | ansible-lint                                         |
| aws                  | cfn-lint, cfn_nag                                    |
| bash                 | shellcheck                                           |
| bom                  | cdxgen                                               |
| Credential scanning  | gitleaks                                             |
| golang               | gosec, staticcheck                                   |
| java                 | cdxgen, gradle, find-sec-bugs, pmd, dependency-check |
| json                 | jq, jsondiff, jsonschema                             |
| kotlin               | detekt                                               |
| kubernetes           | kube-score                                           |
| node.js              | cdxgen, NodeJsScan, retire, eslint, yarn             |
| puppet               | puppet-lint                                          |
| python               | bandit, cdxgen, ossaudit, pipenv                     |
| ruby                 | railroader, cyclonedx-ruby                           |
| rust                 | cargo-audit                                          |
| terraform            | tfsec                                                |
| yaml                 | yamllint                                             |

## Bundled languages/runtime

- jq
- Python 3.6
- OpenJDK 11 (jre)
- Ruby 2.5.5
- Rust
- Node.js 10
- Yarnpkg

## Usage

### Invoking built-in tools

Bandit

```bash
docker run --rm -v <source path>:/app appthreat/sast-scan bandit -r /app
```

dependency-check

```bash
docker run --rm --tmpfs /tmp -v <source path>:/app appthreat/sast-scan /opt/dependency-check/bin/dependency-check.sh -s /app
```

Retire.js

```bash
docker run --rm --tmpfs /tmp -v <source path>:/app appthreat/sast-scan retire -p --path /app
```

### Using custom scan script

Scan python project

```bash
docker run --rm --tmpfs /tmp -v <source path>:/app appthreat/sast-scan scan --src /app --type python --out_dir /app/reports
```

Scan node.js project

```bash
docker run --rm --tmpfs /tmp -v <source path>:/app appthreat/sast-scan scan --src /app --type nodejs --out_dir /app/reports
```

Scan java project

```bash
docker run --rm --tmpfs /tmp -v ~/.m2:/.m2 -v <source path>:/app appthreat/sast-scan scan --src /app --type java --out_dir /app/reports

# For gradle project
docker run --rm --tmpfs /tmp -v ~/.gradle:/.gradle -v <source path>:/app appthreat/sast-scan scan --src /app --type java --out_dir /app/reports
```

## Viewing reports

Reports would be produced in the directory specified for `--out_dir`. In the above examples, it is set to `reports` which will be a directory under the source code root directory.

Some of the reports would be converted to a standard called [SARIF](https://sarifweb.azurewebsites.net/). Such reports would end with the extension `.sarif`. To open and view the sarif files require a viewer such as:

- Online viewer - http://sarifviewer.azurewebsites.net/
- VS Code extension - https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer
- Visual Studio extension - https://marketplace.visualstudio.com/items?itemName=WDGIS.MicrosoftSarifViewer
- Azure DevOps extension - https://marketplace.visualstudio.com/items?itemName=sariftools.sarif-viewer-build-tab

### Tools enabled for SARIF conversion

- Python - bandit
- Node.js - NodeJsScan
- Java - pmd, find-sec-bugs

  **Example reports:**

Online viewer can be used to manually upload the .sarif files as shown.

![Online viewer](docs/sarif-online-viewer.png)

Azure DevOps SARIF plugin can be integrated to show the analysis integrated with the build run as shown.

![Azure DevOps integration](docs/azure-devops.png)

## Integration with Azure DevOps

Refer to the sample yaml [configuration](docs/azure-pipelines.yml.sample) to add sast-scan to an Azure DevOps pipeline.

## Integration with GitHub action

This tool can be used with GitHub actions using this [action](https://github.com/marketplace/actions/sast-scan). All the supported languages can be used.

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

## Alternatives

GitLab [SAST](https://docs.gitlab.com/ee/user/application_security/sast/) uses numerous single purpose [analyzers](https://gitlab.com/gitlab-org/security-products/analyzers) and GoLang based convertors to produce a custom json format. This model has the downside of increasing build times since multiple container images should get downloaded and hence is not suitable for CI environments such as Azure Pipelines, CodeBuild and Google CloudBuild. Plus the license used by GitLab is not opensource even though the analyzers merely wrap existing oss tools!
