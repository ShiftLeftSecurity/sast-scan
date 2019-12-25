# Introduction

This repo builds `appthreat/sast-scan`, a container image with a number of bundled opensource static analysis tools. RedHat's `ubi8/ubi-minimal` is used as a base image instead of the usual alpine to help with enterprise adoption of this tool.

## Bundled tools

| Programming Language | Tools |
| ansible | ansible-lint |
| aws | cfn-lint, cfn-nag |
| bash | shellcheck |
| Credential scanning | gitleaks |
| golang | gosec, staticcheck |
| java | gradle, pmd, dependency-check |
| kotlin | detekt |
| kubernetes | kube-score |
| node.js | retire, eslint, yarn |
| puppet | puppet-lint |
| python | bandit, pipenv |
| ruby | brakeman |
| rust | cargo-audit |
| yaml | yamllint |

## Bundled languages/runtime

- jq
- Python 3.6
- OpenJDK 11 (jre)
- Ruby 2.5.5
- Rust
- Node.js 10
- Yarnpkg
