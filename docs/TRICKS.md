# Tips and tricks

This page captures advanced customisation and tweaks supported by sast-scan.

## Automatic build

Scan can attempt to build certain project types such as Java, go, node.js, rust and csharp using the bundled runtimes. To enable auto build simply pass `--build` argument or set the environment variable `SCAN_AUTO_BUILD` to a non-empty value.

## Workspace path prefix

sast-scan tool is typically invoked using the docker container image with volume mounts. Due to this behaviour, the source path the tools would see would be different to the source path in the developer laptop or in the CI environment.

To override the prefix, simply pass the environment variable `WORKSPACE` with the path that should get prefixed in the reports.

```bash
export WORKSPACE="/home/shiftleft/src"

# To specify url
export WORKSPACE="https://github.com/ShiftLeftSecurity/cdxgen/blob/master"
```

If your organization use `Azure Repos` for hosting git repositories then the above approach would not work because of the way url gets constructed. You can construct the url for Azure Repos as follows:

```bash
export WORKSPACE="$(Build.Repository.Uri)?_a=contents&version=GB$(Build.SourceBranchName)&path="
```

However, note that because of the way `Build.SourceBranchName` is [computed](https://docs.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml) this variable may not work if the branch contains slashes in them such as `feature/foo/bar`. In such cases, the branch name has to be derived based on the variable `Build.SourceBranch` by removing the `/refs/heads` or `/refs/pull/` prefixes.

Let us know if you find a better way to support direct linking for Azure Repos.

## Config file

sast-scan can load configurations automatically from `.sastscanrc` in the repo root directory. This file is a json file containing the keys from [config.py](lib/config.py).

Below is an example.

```json
{
  "scan_type": "java,credscan,bash",
  "scan_tools_args_map": {
    "credscan": [
      "gitleaks",
      "--branch=master",
      "--repo-path=%(src)s",
      "--redact",
      "--report=%(report_fname_prefix)s.json",
      "--format=json"
    ]
  }
}
```

With a local config you can override the scan type and even configure the command line args for the tools as shown.

## Use CI build reference as runGuid

By setting the environment variable `SCAN_ID` you can re-use the CI build reference as the run guid for the reports. This is useful to reverse lookup the pipeline result based on the sast-scan result.
