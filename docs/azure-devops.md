# Integration with Azure DevOps Pipelines

sast-scan has good integration with Azure Pipelines. This repo contains an [example for a yaml pipeline](https://github.com/ShiftLeftSecurity/WebGoat/blob/develop/azure-pipelines.yml) that invokes sast-scan as a build step. The step is reproduced below for convenience.

```yaml
- script: |
    docker run -e "WORKSPACE=https://github.com/ShiftLeftSecurity/WebGoat/blob/$(Build.SourceVersion)" \
      -v $(Build.SourcesDirectory):/app \
      -v $(Build.ArtifactStagingDirectory):/reports \
      shiftleft/sast-scan scan --src /app \
      --out_dir /reports/CodeAnalysisLogs
  displayName: "Perform ShiftLeft Scan"
  continueOnError: "true"
```

## Suggested DevSecOps workflow

This section is mostly common for all dev and CI environments.

### pre-commit hook

Use the example pre-commit script provided under `docs/pre-commit.sh` to enable automatic sast-scan prior to commits.

```bash
cp docs/pre-commit.sh <git repo>/.git/hooks/pre-commit
```

This pre-commit hook performs both credentials and sast-scan. Any identified credential will be displayed in plain-text to enable remediation. sast-scan reports would be stored under `reports` directory which could be added to .gitignore to prevent unwanted commits of the reports.

### Credentials scanning

Include `credscan` along with the type parameter as shown to enable credentials scanning for the branch on the CI. This feature is powered by [gitleaks](https://github.com/zricethezav/gitleaks). Please note that identified secrets are automatically REDACTED in the CI environments to prevent leakage.

### Viewing sast-scan reports

The following extension called [ShiftLeft Scan Reports]() must be installed and enabled by the administrator.

The yaml pipeline should include the below steps to enable the analysis.

```yaml
- task: PublishBuildArtifacts@1
  displayName: "Publish analysis logs"
  inputs:
    PathtoPublish: "$(Build.ArtifactStagingDirectory)/CodeAnalysisLogs"
    ArtifactName: "CodeAnalysisLogs"
    publishLocation: "Container"
```
