#!/usr/bin/env bash
APPDIR=$1
OPTDIR=${APPDIR}/opt
GOSEC_VERSION=2.9.6
TFSEC_VERSION=0.63.1
KUBESEC_VERSION=2.11.4
KUBE_SCORE_VERSION=1.13.0
DETEKT_VERSION=1.19.0
GITLEAKS_VERSION=7.6.1
SC_VERSION=2021.1.2
PMD_VERSION=6.42.0
FSB_VERSION=1.11.0
SB_CONTRIB_VERSION=7.4.7
SB_VERSION=4.5.3
NODE_VERSION=14.5.0
export PATH=$PATH:${APPDIR}/usr/bin:

curl -LO "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
    && tar -C ${APPDIR}/usr/bin/ -xvf node-v${NODE_VERSION}-linux-x64.tar.xz \
    && mv ${APPDIR}/usr/bin/node-v${NODE_VERSION}-linux-x64 ${APPDIR}/usr/bin/nodejs \
    && chmod +x ${APPDIR}/usr/bin/nodejs/bin/node \
    && chmod +x ${APPDIR}/usr/bin/nodejs/bin/npm \
    && rm node-v${NODE_VERSION}-linux-x64.tar.xz
curl -LO "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_amd64.tar.gz" \
    && tar -C ${APPDIR}/usr/bin/ -xvf gosec_${GOSEC_VERSION}_linux_amd64.tar.gz \
    && chmod +x ${APPDIR}/usr/bin/gosec \
    && rm gosec_${GOSEC_VERSION}_linux_amd64.tar.gz
curl -LO "https://github.com/dominikh/go-tools/releases/download/${SC_VERSION}/staticcheck_linux_amd64.tar.gz" \
    && tar -C /tmp -xvf staticcheck_linux_amd64.tar.gz \
    && chmod +x /tmp/staticcheck/staticcheck \
    && cp /tmp/staticcheck/staticcheck ${APPDIR}/usr/bin/staticcheck \
    && rm staticcheck_linux_amd64.tar.gz
curl -L "https://github.com/zricethezav/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks-linux-amd64" -o "${APPDIR}/usr/bin/gitleaks" \
    && chmod +x ${APPDIR}/usr/bin/gitleaks \
    && curl -L "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64" -o "${APPDIR}/usr/bin/tfsec" \
    && chmod +x ${APPDIR}/usr/bin/tfsec
curl -L "https://github.com/zegl/kube-score/releases/download/v${KUBE_SCORE_VERSION}/kube-score_${KUBE_SCORE_VERSION}_linux_amd64" -o "${APPDIR}/usr/bin/kube-score" \
    && chmod +x ${APPDIR}/usr/bin/kube-score \
    && wget "https://github.com/pmd/pmd/releases/download/pmd_releases%2F${PMD_VERSION}/pmd-bin-${PMD_VERSION}.zip" \
    && unzip -q pmd-bin-${PMD_VERSION}.zip -d ${OPTDIR}/ \
    && rm pmd-bin-${PMD_VERSION}.zip \
    && mv ${OPTDIR}/pmd-bin-${PMD_VERSION} ${OPTDIR}/pmd-bin
curl -L "https://github.com/detekt/detekt/releases/download/v${DETEKT_VERSION}/detekt-cli-${DETEKT_VERSION}-all.jar" -o "${APPDIR}/usr/bin/detekt-cli.jar" \
    && curl -LO "https://github.com/controlplaneio/kubesec/releases/download/v${KUBESEC_VERSION}/kubesec_linux_amd64.tar.gz" \
    && tar -C ${APPDIR}/usr/bin/ -xvf kubesec_linux_amd64.tar.gz \
    && rm kubesec_linux_amd64.tar.gz \
    && curl -LO "https://github.com/spotbugs/spotbugs/releases/download/${SB_VERSION}/spotbugs-${SB_VERSION}.tgz" \
    && tar -C ${OPTDIR}/ -xvf spotbugs-${SB_VERSION}.tgz \
    && rm spotbugs-${SB_VERSION}.tgz
curl -LO "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FSB_VERSION}/findsecbugs-plugin-${FSB_VERSION}.jar" \
    && mv findsecbugs-plugin-${FSB_VERSION}.jar ${OPTDIR}/spotbugs-${SB_VERSION}/plugin/findsecbugs-plugin.jar \
    && curl -LO "https://repo1.maven.org/maven2/com/mebigfatguy/sb-contrib/sb-contrib/${SB_CONTRIB_VERSION}/sb-contrib-${SB_CONTRIB_VERSION}.jar" \
    && mv sb-contrib-${SB_CONTRIB_VERSION}.jar ${OPTDIR}/spotbugs-${SB_VERSION}/plugin/sb-contrib.jar \
    && mv ${OPTDIR}/spotbugs-${SB_VERSION} ${OPTDIR}/spotbugs \
    && php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" && php composer-setup.php \
    && mv composer.phar ${APPDIR}/usr/bin/composer \
    && rm composer-setup.php
