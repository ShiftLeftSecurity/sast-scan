FROM quay.io/appthreat/scan-base as builder

ARG CLI_VERSION
ARG BUILD_DATE

ENV GOSEC_VERSION=2.1.0 \
    TFSEC_VERSION=0.16.0 \
    KUBESEC_VERSION=2.3.1 \
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
    FSB_VERSION=1.10.1 \
    FB_CONTRIB_VERSION=7.4.7 \
    SB_VERSION=4.0.0-beta4 \
    GO_VERSION=1.13.6 \
    GOPATH=/opt/app-root/go \
    PATH=${PATH}:${GRADLE_HOME}/bin:/opt/app-root/src/.cargo/bin:/opt/dependency-check/bin/:${GOPATH}/bin:

USER root

RUN mkdir -p /usr/local/bin/appthreat \
    && curl -LO "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_amd64.tar.gz" \
    && tar -C /usr/local/bin/appthreat/ -xvf gosec_${GOSEC_VERSION}_linux_amd64.tar.gz \
    && chmod +x /usr/local/bin/appthreat/gosec \
    && rm gosec_${GOSEC_VERSION}_linux_amd64.tar.gz
RUN curl -LO "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
    && unzip -q gradle-${GRADLE_VERSION}-bin.zip -d /opt/ \
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
    && rm staticcheck_linux_amd64.tar.gz
RUN curl -L "https://github.com/zricethezav/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks-linux-amd64" -o "/usr/local/bin/appthreat/gitleaks" \
    && chmod +x /usr/local/bin/appthreat/gitleaks \
    && curl -L "https://github.com/liamg/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64" -o "/usr/local/bin/appthreat/tfsec" \
    && chmod +x /usr/local/bin/appthreat/tfsec \
    && rm shellcheck-stable.linux.x86_64.tar.xz
RUN curl -L "https://github.com/zegl/kube-score/releases/download/v${KUBE_SCORE_VERSION}/kube-score_${KUBE_SCORE_VERSION}_linux_amd64" -o "/usr/local/bin/appthreat/kube-score" \
    && chmod +x /usr/local/bin/appthreat/kube-score \
    && wget "https://github.com/pmd/pmd/releases/download/pmd_releases%2F${PMD_VERSION}/pmd-bin-${PMD_VERSION}.zip" \
    && unzip -q pmd-bin-${PMD_VERSION}.zip -d /opt/ \
    && rm pmd-bin-${PMD_VERSION}.zip \
    && curl -L "https://github.com/stedolan/jq/releases/download/jq-${JQ_VERSION}/jq-linux64" -o "/usr/local/bin/appthreat/jq" \
    && chmod +x /usr/local/bin/appthreat/jq \
    && curl -LO "https://dl.bintray.com/jeremy-long/owasp/dependency-check-${DC_VERSION}-release.zip" \
    && unzip -q dependency-check-${DC_VERSION}-release.zip -d /opt/ \
    && rm dependency-check-${DC_VERSION}-release.zip \
    && chmod +x /opt/dependency-check/bin/dependency-check.sh
RUN curl -L "https://github.com/arturbosch/detekt/releases/download/${DETEKT_VERSION}/detekt-cli-${DETEKT_VERSION}-all.jar" -o "/usr/local/bin/appthreat/detekt-cli.jar" \
    && curl -LO "https://github.com/controlplaneio/kubesec/releases/download/v${KUBESEC_VERSION}/kubesec_linux_amd64.tar.gz" \
    && tar -C /usr/local/bin/appthreat/ -xvf kubesec_linux_amd64.tar.gz \
    && rm kubesec_linux_amd64.tar.gz \
    && curl -LO "https://repo.maven.apache.org/maven2/com/github/spotbugs/spotbugs/${SB_VERSION}/spotbugs-${SB_VERSION}.zip" \
    && unzip -q spotbugs-${SB_VERSION}.zip -d /opt/ \
    && curl -LO "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FSB_VERSION}/findsecbugs-plugin-${FSB_VERSION}.jar" \
    && mv findsecbugs-plugin-${FSB_VERSION}.jar /opt/spotbugs-${SB_VERSION}/plugin/findsecbugs-plugin.jar \
    && curl -LO "https://repo1.maven.org/maven2/com/mebigfatguy/fb-contrib/fb-contrib/${FB_CONTRIB_VERSION}/fb-contrib-${FB_CONTRIB_VERSION}.jar" \
    && mv fb-contrib-${FB_CONTRIB_VERSION}.jar /opt/spotbugs-${SB_VERSION}/plugin/fb-contrib.jar
RUN gem install -q railroader cfn-nag puppet-lint cyclonedx-ruby && gem cleanup -q

FROM quay.io/appthreat/scan-base-slim as sast-scan-tools

LABEL maintainer="AppThreat" \
      org.label-schema.schema-version="1.0" \
      org.label-schema.vendor="AppThreat" \
      org.label-schema.name="sast-scan" \
      org.label-schema.version=$CLI_VERSION \
      org.label-schema.license="MIT" \
      org.label-schema.description="Container with various opensource static analysis security testing tools (shellcheck, gosec, tfsec, gitleaks, ...) for multiple programming languages" \
      org.label-schema.url="https://appthreat.io" \
      org.label-schema.usage="https://github.com/appthreat/sast-scan" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/appthreat/sast-scan.git" \
      org.label-schema.docker.cmd="docker run --rm -it --name sast-scan appthreat/sast-scan"

ENV APP_SRC_DIR=/usr/local/src \
    PMD_CMD="/opt/pmd-bin/bin/run.sh pmd" \
    SPOTBUGS_HOME=/opt/spotbugs \
    JAVA_HOME=/usr/lib/jvm/jre-11 \
    PATH=/usr/local/src/:${PATH}:/usr/local/go/bin:/opt/.cargo/bin:/opt/dependency-check/bin/:

COPY --from=builder /usr/local/bin/appthreat /usr/local/bin
COPY --from=builder /usr/local/lib64/gems /usr/local/lib64/gems
COPY --from=builder /usr/local/share/gems /usr/local/share/gems
COPY --from=builder /usr/local/bin/railroader /usr/local/bin/railroader
COPY --from=builder /usr/local/bin/cfn_nag /usr/local/bin/cfn_nag
COPY --from=builder /usr/local/bin/puppet-lint /usr/local/bin/puppet-lint
COPY --from=builder /usr/local/bin/cyclonedx-ruby /usr/local/bin/cyclonedx-ruby
COPY --from=builder /opt/app-root/src/.cargo/bin /opt/.cargo/bin
COPY rules-pmd.xml /usr/local/src/
COPY spotbugs /usr/local/src/spotbugs
COPY --from=builder /opt/dependency-check /opt/dependency-check
COPY --from=builder /opt/pmd-bin-6.20.0 /opt/pmd-bin
COPY --from=builder /opt/spotbugs-4.0.0-beta4 /opt/spotbugs
COPY requirements.txt /usr/local/src/
COPY scan /usr/local/src/
COPY lib /usr/local/src/lib

USER root

RUN pip3 install --no-cache-dir wheel bandit ansible-lint pipenv cfn-lint yamllint ossaudit nodejsscan \
    && pip3 install --no-cache-dir -r /usr/local/src/requirements.txt \
    && npm install -g retire @appthreat/cdxgen eslint \
    && chmod +x /usr/local/src/scan \
    && microdnf remove -y ruby-devel xz shadow-utils \
    && mkdir -p /.cache /opt/dependency-check/data

WORKDIR /usr/local/src

CMD [ "python3", "/usr/local/src/scan" ]
