# Tips and tricks

This page captures advanced customisation and tweaks supported by sast-scan.

## Workspace path prefix

sast-scan tool is typically invoked using the docker container image with volume mounts. Due to this behaviour, the source path the tools would see would be different to the source path in the developer laptop or in the CI environment.

To override the prefix, simply pass the environment variable `WORKSPACE` with the path that should get prefixed in the reports.

```bash
export WORKSPACE="/home/appthreat/src"

# To specify url
export WORKSPACE="https://github.com/appthreat/cdxgen/blob/master
```
