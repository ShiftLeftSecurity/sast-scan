FROM registry.access.redhat.com/ubi8/python-36 as builder

ARG CLI_VERSION
ARG BUILD_DATE

ENV GOSEC_VERSION=2.1.0 \
    TFSEC_VERSION=0.13.0 \
    KUBE_SCORE_VERSION=1.4.0 \
    DETEKT_VERSION=1.3.0 \
    GITLEAKS_VERSION=3.0.3 \
    GRADLE_VERSION=6.0.1 \
    GRADLE_HOME=/opt/gradle-${GRADLE_VERSION} \
    SC_VERSION=2019.2.3 \
    PMD_VERSION=6.20.0 \
    PMD_CMD="/opt/pmd-bin-${PMD_VERSION}/bin/run.sh pmd" \
    JQ_VERSION=1.6 \
    DC_VERSION=5.2.4 \
    REMIC_VERSION=0.0.2 \
    GOPATH=/opt/app-root/go \
    PATH=${PATH}:${GRADLE_HOME}/bin:/opt/app-root/src/.cargo/bin:/opt/dependency-check/bin/:${GOPATH}/bin:

USER root

RUN mkdir -p /usr/local/bin/appthreat \
    && curl -LO "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_amd64.tar.gz" \
    && tar -C /usr/local/bin/appthreat/ -xvf gosec_${GOSEC_VERSION}_linux_amd64.tar.gz \
    && chmod +x /usr/local/bin/appthreat/gosec \
    && rm gosec_${GOSEC_VERSION}_linux_amd64.tar.gz \
    && yum update -y \
    && yum install -y ruby ruby-libs ruby-devel rubygems nodejs golang \
    && curl -LO "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
    && unzip gradle-${GRADLE_VERSION}-bin.zip -d /opt/ \
    && chmod +x /opt/gradle-${GRADLE_VERSION}/bin/gradle \
    && rm gradle-${GRADLE_VERSION}-bin.zip \
    && curl -LO "https://storage.googleapis.com/shellcheck/shellcheck-stable.linux.x86_64.tar.xz" \
    && tar -C /tmp/ -xvf shellcheck-stable.linux.x86_64.tar.xz \
    && cp /tmp/shellcheck-stable/shellcheck /usr/local/bin/appthreat/shellcheck \
    && chmod +x /usr/local/bin/appthreat/shellcheck \
    && curl -LO "https://github.com/dominikh/go-tools/releases/download/${SC_VERSION}/staticcheck_linux_amd64.tar.gz" \
    && tar -C /tmp -xvf staticcheck_linux_amd64.tar.gz \
    && chmod +x /tmp/staticcheck/staticcheck \
    && cp /tmp/staticcheck/staticcheck /usr/local/bin/appthreat/staticcheck \
    && rm staticcheck_linux_amd64.tar.gz \
    && curl -L "https://github.com/zricethezav/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks-linux-amd64" -o "/usr/local/bin/appthreat/gitleaks" \
    && chmod +x /usr/local/bin/appthreat/gitleaks \
    && curl -L "https://github.com/liamg/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64" -o "/usr/local/bin/appthreat/tfsec" \
    && chmod +x /usr/local/bin/appthreat/tfsec \
    && rm shellcheck-stable.linux.x86_64.tar.xz \
    && curl -L https://sh.rustup.rs > rust-installer.sh \
    && chmod +x rust-installer.sh \
    && bash rust-installer.sh -y \
    && rm rust-installer.sh \
    && cargo install cargo-audit \
    && curl -L "https://github.com/zegl/kube-score/releases/download/v${KUBE_SCORE_VERSION}/kube-score_${KUBE_SCORE_VERSION}_linux_amd64" -o "/usr/local/bin/appthreat/kube-score" \
    && chmod +x /usr/local/bin/appthreat/kube-score \
    && wget "https://github.com/pmd/pmd/releases/download/pmd_releases%2F${PMD_VERSION}/pmd-bin-${PMD_VERSION}.zip" \
    && unzip pmd-bin-${PMD_VERSION}.zip -d /opt/ \
    && rm pmd-bin-${PMD_VERSION}.zip \
    && curl -L "https://github.com/stedolan/jq/releases/download/jq-${JQ_VERSION}/jq-linux64" -o "/usr/local/bin/appthreat/jq" \
    && chmod +x /usr/local/bin/appthreat/jq \
    && curl -LO "https://dl.bintray.com/jeremy-long/owasp/dependency-check-${DC_VERSION}-release.zip" \
    && unzip dependency-check-${DC_VERSION}-release.zip -d /opt/ \
    && rm dependency-check-${DC_VERSION}-release.zip \
    && chmod +x /opt/dependency-check/bin/dependency-check.sh \
    && curl -L "https://github.com/arturbosch/detekt/releases/download/${DETEKT_VERSION}/detekt-cli-${DETEKT_VERSION}-all.jar" -o "/usr/local/bin/appthreat/detekt-cli.jar" \
    && curl -LO "https://github.com/knqyf263/remic/releases/download/v${REMIC_VERSION}/remic_${REMIC_VERSION}_Linux-64bit.tar.gz" \
    && tar -C /usr/local/bin/appthreat/ -xvf remic_${REMIC_VERSION}_Linux-64bit.tar.gz \
    && rm remic_${REMIC_VERSION}_Linux-64bit.tar.gz \
    && gem install brakeman cfn-nag puppet-lint cyclonedx-ruby

FROM registry.access.redhat.com/ubi8/ubi-minimal as tools

LABEL maintainer="AppThreat" \
      org.label-schema.schema-version="1.0" \
      org.label-schema.vendor="AppThreat" \
      org.label-schema.name="sast-scan" \
      org.label-schema.version=$CLI_VERSION \
      org.label-schema.license="MIT" \
      org.label-schema.description="Container with various opensource static analysis tools (shellcheck, gosec, tfsec, gitleaks, ...) for multiple programming languages" \
      org.label-schema.url="https://appthreat.io" \
      org.label-schema.usage="https://github.com/appthreat/sast-scan" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/appthreat/sast-scan.git" \
      org.label-schema.docker.cmd="docker run --rm -it --name sast-scan appthreat/sast-scan"

ENV GOSEC_VERSION=2.1.0 \
    TFSEC_VERSION=0.13.0 \
    KUBE_SCORE_VERSION=1.4.0 \
    DETEKT_VERSION=1.3.0 \
    GITLEAKS_VERSION=3.0.3 \
    SC_VERSION=2019.2.3 \
    PMD_VERSION=6.20.0 \
    PMD_CMD="/opt/pmd-bin/bin/run.sh pmd" \
    JAVA_HOME=/usr/lib/jvm/jre-11 \
    JQ_VERSION=1.6 \
    DC_VERSION=5.2.4 \
    REMIC_VERSION=0.0.2 \
    PATH=${PATH}:/opt/.cargo/bin:/opt/dependency-check/bin/:

COPY --from=builder /usr/local/bin/appthreat /usr/local/bin
COPY --from=builder /usr/local/share/gems /usr/local/share/gems
COPY --from=builder /usr/local/bin/brakeman /usr/local/bin/brakeman
COPY --from=builder /usr/local/bin/cfn_nag /usr/local/bin/cfn_nag
COPY --from=builder /usr/local/bin/puppet-lint /usr/local/bin/puppet-lint
COPY --from=builder /usr/local/bin/cyclonedx-ruby /usr/local/bin/cyclonedx-ruby
COPY --from=builder /opt/dependency-check /opt/dependency-check
COPY --from=builder /opt/pmd-bin-6.20.0 /opt/pmd-bin
COPY --from=builder /opt/app-root/src/.cargo/bin /opt/.cargo/bin

USER root

RUN microdnf update -y \
    && microdnf install -y python36 ruby ruby-libs java-11-openjdk-headless nodejs git-core \
    && pip3 install --upgrade setuptools \
    && pip3 install --no-cache-dir wheel bandit ansible-lint pipenv cfn-lint yamllint ossaudit cyclonedx-bom \
    && npm install -g yarn retire eslint @cyclonedx/bom \
    && mkdir -p /.cache /opt/dependency-check/data \
    && chown -R nobody:root /opt/dependency-check/data \
    && chown -R nobody:root /.cache \
    && microdnf clean all \
    && rm -rf /tmp/

COPY scan.py /usr/local/src/
COPY rules-pmd.xml /usr/local/src/

WORKDIR /usr/local/src

# Run as default user
USER nobody

CMD [ "python3", "/usr/local/src/scan.py" ]
