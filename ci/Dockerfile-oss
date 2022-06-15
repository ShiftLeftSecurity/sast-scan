FROM shiftleft/scan-base as builder

ARG CLI_VERSION
ARG BUILD_DATE

ENV GOSEC_VERSION=2.9.6 \
    TFSEC_VERSION=0.63.1 \
    KUBESEC_VERSION=2.11.4 \
    KUBE_SCORE_VERSION=1.13.0 \
    SHELLCHECK_VERSION=0.7.2 \
    DETEKT_VERSION=1.19.0 \
    GITLEAKS_VERSION=7.6.1 \
    GRADLE_VERSION=7.2 \
    GRADLE_HOME=/opt/gradle-${GRADLE_VERSION} \
    MAVEN_VERSION=3.8.6 \
    MAVEN_HOME=/opt/apache-maven-${MAVEN_VERSION} \
    SC_VERSION=2021.1.2 \
    PMD_VERSION=6.42.0 \
    PMD_CMD="/opt/pmd-bin-${PMD_VERSION}/bin/run.sh pmd" \
    JQ_VERSION=1.6 \
    FSB_VERSION=1.11.0 \
    SB_CONTRIB_VERSION=7.4.7 \
    SB_VERSION=4.5.3 \
    GOPATH=/opt/app-root/go \
    PATH=${PATH}:${GRADLE_HOME}/bin:${GOPATH}/bin:

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
    && curl -LO "https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.linux.x86_64.tar.xz" \
    && tar -C /tmp/ -xvf shellcheck-v${SHELLCHECK_VERSION}.linux.x86_64.tar.xz \
    && cp /tmp/shellcheck-v${SHELLCHECK_VERSION}/shellcheck /usr/local/bin/shiftleft/shellcheck \
    && chmod +x /usr/local/bin/shiftleft/shellcheck \
    && curl -LO "https://github.com/dominikh/go-tools/releases/download/${SC_VERSION}/staticcheck_linux_amd64.tar.gz" \
    && tar -C /tmp -xvf staticcheck_linux_amd64.tar.gz \
    && chmod +x /tmp/staticcheck/staticcheck \
    && cp /tmp/staticcheck/staticcheck /usr/local/bin/shiftleft/staticcheck \
    && rm staticcheck_linux_amd64.tar.gz
RUN curl -L "https://github.com/zricethezav/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks-linux-amd64" -o "/usr/local/bin/shiftleft/gitleaks" \
    && chmod +x /usr/local/bin/shiftleft/gitleaks \
    && curl -L "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64" -o "/usr/local/bin/shiftleft/tfsec" \
    && chmod +x /usr/local/bin/shiftleft/tfsec \
    && rm shellcheck-v${SHELLCHECK_VERSION}.linux.x86_64.tar.xz
RUN curl -L "https://github.com/zegl/kube-score/releases/download/v${KUBE_SCORE_VERSION}/kube-score_${KUBE_SCORE_VERSION}_linux_amd64" -o "/usr/local/bin/shiftleft/kube-score" \
    && chmod +x /usr/local/bin/shiftleft/kube-score \
    && wget "https://github.com/pmd/pmd/releases/download/pmd_releases%2F${PMD_VERSION}/pmd-bin-${PMD_VERSION}.zip" \
    && unzip -q pmd-bin-${PMD_VERSION}.zip -d /opt/ \
    && rm pmd-bin-${PMD_VERSION}.zip \
    && curl -L "https://github.com/stedolan/jq/releases/download/jq-${JQ_VERSION}/jq-linux64" -o "/usr/local/bin/shiftleft/jq" \
    && chmod +x /usr/local/bin/shiftleft/jq
RUN curl -L "https://github.com/detekt/detekt/releases/download/v${DETEKT_VERSION}/detekt-cli-${DETEKT_VERSION}-all.jar" -o "/usr/local/bin/shiftleft/detekt-cli.jar" \
    && curl -LO "https://github.com/controlplaneio/kubesec/releases/download/v${KUBESEC_VERSION}/kubesec_linux_amd64.tar.gz" \
    && tar -C /usr/local/bin/shiftleft/ -xvf kubesec_linux_amd64.tar.gz \
    && rm kubesec_linux_amd64.tar.gz \
    && curl -LO "https://github.com/spotbugs/spotbugs/releases/download/${SB_VERSION}/spotbugs-${SB_VERSION}.tgz" \
    && tar -C /opt/ -xvf spotbugs-${SB_VERSION}.tgz \
    && rm spotbugs-${SB_VERSION}.tgz \
    && curl -LO "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FSB_VERSION}/findsecbugs-plugin-${FSB_VERSION}.jar" \
    && mv findsecbugs-plugin-${FSB_VERSION}.jar /opt/spotbugs-${SB_VERSION}/plugin/findsecbugs-plugin.jar \
    && curl -LO "https://repo1.maven.org/maven2/com/mebigfatguy/sb-contrib/sb-contrib/${SB_CONTRIB_VERSION}/sb-contrib-${SB_CONTRIB_VERSION}.jar" \
    && mv sb-contrib-${SB_CONTRIB_VERSION}.jar /opt/spotbugs-${SB_VERSION}/plugin/sb-contrib.jar

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
      org.label-schema.docker.cmd="docker run --rm -it --name sast-scan shiftleft/scan-oss"

ENV APP_SRC_DIR=/usr/local/src \
    DEPSCAN_CMD="/usr/local/bin/depscan" \
    MVN_CMD="/opt/apache-maven/bin/mvn" \
    PMD_CMD="/opt/pmd-bin/bin/run.sh pmd" \
    SB_VERSION=4.5.3 \
    PMD_VERSION=6.42.0 \
    PMD_JAVA_OPTS="--enable-preview" \
    SPOTBUGS_HOME=/opt/spotbugs \
    JAVA_HOME=/usr/lib/jvm/jre-11-openjdk \
    SCAN_JAVA_HOME=/usr/lib/jvm/jre-11-openjdk \
    SCAN_JAVA_11_HOME=/usr/lib/jvm/jre-11-openjdk \
    SCAN_JAVA_8_HOME=/usr/lib/jvm/jre-1.8.0 \
    GRADLE_VERSION=7.2 \
    GRADLE_HOME=/opt/gradle \
    GRADLE_CMD=gradle \
    MAVEN_VERSION=3.8.6 \
    MAVEN_HOME=/opt/apache-maven \
    PYTHONUNBUFFERED=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    GO111MODULE=auto \
    GOARCH=amd64 \
    GOOS=linux \
    CGO_ENABLED=0 \
    NVD_EXCLUDE_TYPES="o,h" \
    PATH=/usr/local/src/:${PATH}:/opt/gradle/bin:/opt/apache-maven/bin:/usr/local/go/bin:

COPY --from=builder /usr/local/bin/shiftleft /usr/local/bin
COPY --from=builder /opt/pmd-bin-${PMD_VERSION} /opt/pmd-bin
COPY --from=builder /opt/spotbugs-${SB_VERSION} /opt/spotbugs
COPY --from=builder /opt/gradle-${GRADLE_VERSION} /opt/gradle
COPY --from=builder /opt/apache-maven-${MAVEN_VERSION} /opt/apache-maven
COPY tools_config/ /usr/local/src/
COPY requirements.txt /usr/local/src/

USER root

RUN microdnf install python38-devel && pip3 install --no-cache-dir wheel \
    && python3 -m pip install --upgrade pip \
    && pip3 install --no-cache-dir -r /usr/local/src/requirements.txt \
    && pip3 install --no-cache-dir njsscan \
    && npm install --no-audit --progress=false --only=production -g @appthreat/cdxgen @microsoft/rush --unsafe-perm \
    && mkdir -p /opt/phpsast && cd /opt/phpsast && composer require --quiet --no-cache --dev vimeo/psalm \
    && composer require --quiet --no-cache --dev phpstan/phpstan \
    && composer require --quiet --no-cache --dev phpstan/extension-installer \
    && microdnf remove -y python38-devel php-fpm php-devel php-pear automake make gcc gcc-c++ libtool \
    && microdnf clean all

WORKDIR /app

COPY scan /usr/local/src/
COPY lib /usr/local/src/lib

CMD [ "python3", "/usr/local/src/scan" ]
