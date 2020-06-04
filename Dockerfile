FROM shiftleft/scan-base as builder

ARG CLI_VERSION
ARG BUILD_DATE

ENV GOSEC_VERSION=2.2.0 \
    TFSEC_VERSION=0.19.0 \
    KUBESEC_VERSION=2.3.1 \
    KUBE_SCORE_VERSION=1.5.1 \
    DETEKT_VERSION=1.6.0 \
    GITLEAKS_VERSION=4.1.0 \
    GRADLE_VERSION=6.0.1 \
    GRADLE_HOME=/opt/gradle-${GRADLE_VERSION} \
    MAVEN_VERSION=3.6.3 \
    MAVEN_HOME=/opt/apache-maven-${MAVEN_VERSION} \
    SC_VERSION=2020.1.3 \
    PMD_VERSION=6.22.0 \
    PMD_CMD="/opt/pmd-bin-${PMD_VERSION}/bin/run.sh pmd" \
    JQ_VERSION=1.6 \
    FSB_VERSION=1.10.1 \
    FB_CONTRIB_VERSION=7.4.7 \
    SB_VERSION=4.0.1 \
    GOPATH=/opt/app-root/go \
    SHIFTLEFT_HOME=/opt/sl-cli \
    PATH=${PATH}:${GRADLE_HOME}/bin:/opt/app-root/src/.cargo/bin:${GOPATH}/bin:

USER root

RUN mkdir -p /usr/local/bin/shiftleft \
    && curl -LO "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_amd64.tar.gz" \
    && tar -C /usr/local/bin/shiftleft/ -xvf gosec_${GOSEC_VERSION}_linux_amd64.tar.gz \
    && chmod +x /usr/local/bin/shiftleft/gosec \
    && rm gosec_${GOSEC_VERSION}_linux_amd64.tar.gz
RUN curl -LO "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
    && unzip -q gradle-${GRADLE_VERSION}-bin.zip -d /opt/ \
    && chmod +x /opt/gradle-${GRADLE_VERSION}/bin/gradle \
    && rm gradle-${GRADLE_VERSION}-bin.zip \
    && curl -LO "https://downloads.apache.org/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.zip" \
    && unzip -q apache-maven-${MAVEN_VERSION}-bin.zip -d /opt/ \
    && chmod +x /opt/apache-maven-${MAVEN_VERSION}/bin/mvn \
    && rm apache-maven-${MAVEN_VERSION}-bin.zip \
    && curl -LO "https://storage.googleapis.com/shellcheck/shellcheck-stable.linux.x86_64.tar.xz" \
    && tar -C /tmp/ -xvf shellcheck-stable.linux.x86_64.tar.xz \
    && cp /tmp/shellcheck-stable/shellcheck /usr/local/bin/shiftleft/shellcheck \
    && chmod +x /usr/local/bin/shiftleft/shellcheck \
    && curl -LO "https://github.com/dominikh/go-tools/releases/download/${SC_VERSION}/staticcheck_linux_amd64.tar.gz" \
    && tar -C /tmp -xvf staticcheck_linux_amd64.tar.gz \
    && chmod +x /tmp/staticcheck/staticcheck \
    && cp /tmp/staticcheck/staticcheck /usr/local/bin/shiftleft/staticcheck \
    && rm staticcheck_linux_amd64.tar.gz
RUN curl -L "https://github.com/zricethezav/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks-linux-amd64" -o "/usr/local/bin/shiftleft/gitleaks" \
    && chmod +x /usr/local/bin/shiftleft/gitleaks \
    && curl -L "https://github.com/liamg/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64" -o "/usr/local/bin/shiftleft/tfsec" \
    && chmod +x /usr/local/bin/shiftleft/tfsec \
    && rm shellcheck-stable.linux.x86_64.tar.xz
RUN curl -L "https://github.com/zegl/kube-score/releases/download/v${KUBE_SCORE_VERSION}/kube-score_${KUBE_SCORE_VERSION}_linux_amd64" -o "/usr/local/bin/shiftleft/kube-score" \
    && chmod +x /usr/local/bin/shiftleft/kube-score \
    && wget "https://github.com/pmd/pmd/releases/download/pmd_releases%2F${PMD_VERSION}/pmd-bin-${PMD_VERSION}.zip" \
    && unzip -q pmd-bin-${PMD_VERSION}.zip -d /opt/ \
    && rm pmd-bin-${PMD_VERSION}.zip \
    && curl -L "https://github.com/stedolan/jq/releases/download/jq-${JQ_VERSION}/jq-linux64" -o "/usr/local/bin/shiftleft/jq" \
    && chmod +x /usr/local/bin/shiftleft/jq
RUN curl -L "https://github.com/arturbosch/detekt/releases/download/${DETEKT_VERSION}/detekt-cli-${DETEKT_VERSION}-all.jar" -o "/usr/local/bin/shiftleft/detekt-cli.jar" \
    && curl -LO "https://github.com/controlplaneio/kubesec/releases/download/v${KUBESEC_VERSION}/kubesec_linux_amd64.tar.gz" \
    && tar -C /usr/local/bin/shiftleft/ -xvf kubesec_linux_amd64.tar.gz \
    && rm kubesec_linux_amd64.tar.gz \
    && curl -LO "https://repo.maven.apache.org/maven2/com/github/spotbugs/spotbugs/${SB_VERSION}/spotbugs-${SB_VERSION}.zip" \
    && unzip -q spotbugs-${SB_VERSION}.zip -d /opt/ \
    && rm spotbugs-${SB_VERSION}.zip \
    && curl -LO "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FSB_VERSION}/findsecbugs-plugin-${FSB_VERSION}.jar" \
    && mv findsecbugs-plugin-${FSB_VERSION}.jar /opt/spotbugs-${SB_VERSION}/plugin/findsecbugs-plugin.jar \
    && curl -LO "https://repo1.maven.org/maven2/com/mebigfatguy/fb-contrib/fb-contrib/${FB_CONTRIB_VERSION}/fb-contrib-${FB_CONTRIB_VERSION}.jar" \
    && mv fb-contrib-${FB_CONTRIB_VERSION}.jar /opt/spotbugs-${SB_VERSION}/plugin/fb-contrib.jar \
    && curl "https://cdn.shiftleft.io/download/sl" > /usr/local/bin/shiftleft/sl \
    && chmod a+rx /usr/local/bin/shiftleft/sl \
    && mkdir -p /opt/sl-cli
RUN gem install -q cfn-nag puppet-lint cyclonedx-ruby && gem cleanup -q

FROM shiftleft/scan-base-slim as sast-scan-tools

LABEL maintainer="ShiftLeftSecurity" \
      org.label-schema.schema-version="1.0" \
      org.label-schema.vendor="shiftleft" \
      org.label-schema.name="sast-scan" \
      org.label-schema.version=$CLI_VERSION \
      org.label-schema.license="GPL-3.0-or-later" \
      org.label-schema.description="Container with various opensource static analysis security testing tools (shellcheck, gosec, tfsec, gitleaks, ...) for multiple programming languages" \
      org.label-schema.url="https://www.shiftleft.io" \
      org.label-schema.usage="https://github.com/ShiftLeftSecurity/sast-scan" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/ShiftLeftSecurity/sast-scan.git" \
      org.label-schema.docker.cmd="docker run --rm -it --name sast-scan shiftleft/sast-scan"

ENV APP_SRC_DIR=/usr/local/src \
    DEPSCAN_CMD="/usr/local/bin/depscan" \
    MVN_CMD="/opt/apache-maven/bin/mvn" \
    PMD_CMD="/opt/pmd-bin/bin/run.sh pmd" \
    SB_VERSION=4.0.1 \
    PMD_VERSION=6.22.0 \
    PMD_JAVA_OPTS="" \
    SPOTBUGS_HOME=/opt/spotbugs \
    JAVA_HOME=/usr/lib/jvm/jre-11-openjdk \
    SCAN_JAVA_HOME=/usr/lib/jvm/jre-11-openjdk \
    SCAN_JAVA_11_HOME=/usr/lib/jvm/jre-11-openjdk \
    SCAN_JAVA_8_HOME=/usr/lib/jvm/jre-1.8.0 \
    GRADLE_VERSION=6.0.1 \
    GRADLE_HOME=/opt/gradle \
    GRADLE_CMD=gradle \
    MAVEN_VERSION=3.6.3 \
    MAVEN_HOME=/opt/apache-maven \
    PYTHONUNBUFFERED=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    SHIFTLEFT_HOME=/opt/sl-cli \
    GO111MODULE=auto \
    GOARCH=amd64 \
    GOOS=linux \
    PATH=/usr/local/src/:${PATH}:/opt/gradle/bin:/opt/apache-maven/bin:/usr/local/go/bin:/opt/.cargo/bin:/opt/sl-cli:

COPY --from=builder /usr/local/bin/shiftleft /usr/local/bin
COPY --from=builder /usr/local/lib64/gems /usr/local/lib64/gems
COPY --from=builder /usr/local/share/gems /usr/local/share/gems
COPY --from=builder /usr/local/bin/cfn_nag /usr/local/bin/cfn_nag
COPY --from=builder /usr/local/bin/puppet-lint /usr/local/bin/puppet-lint
COPY --from=builder /usr/local/bin/cyclonedx-ruby /usr/local/bin/cyclonedx-ruby
COPY --from=builder /opt/app-root/src/.cargo/bin /opt/.cargo/bin
COPY spotbugs /usr/local/src/spotbugs
COPY --from=builder /opt/pmd-bin-${PMD_VERSION} /opt/pmd-bin
COPY --from=builder /opt/spotbugs-${SB_VERSION} /opt/spotbugs
COPY --from=builder /opt/gradle-${GRADLE_VERSION} /opt/gradle
COPY --from=builder /opt/apache-maven-${MAVEN_VERSION} /opt/apache-maven
COPY --from=builder /opt/sl-cli /opt/sl-cli
COPY rules-pmd.xml /usr/local/src/
COPY requirements.txt /usr/local/src/

USER root

RUN pip3 install --no-cache-dir wheel \
    && pip3 install --no-cache-dir appthreat-depscan \
    && mv /usr/local/bin/scan /usr/local/bin/depscan \
    && pip3 install --no-cache-dir -r /usr/local/src/requirements.txt \
    && npm install --only=production -g @appthreat/cdxgen \
    && microdnf remove -y ruby-devel

WORKDIR /app
COPY credscan-config.toml /usr/local/src/
COPY scan /usr/local/src/
COPY lib /usr/local/src/lib

CMD [ "python3", "/usr/local/src/scan" ]
