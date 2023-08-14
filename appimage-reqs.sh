#!/usr/bin/env bash
set -xe
#ARCH=arm64 # This should be set in the builder docker file
APPDIR=$1
OPTDIR=${APPDIR}/opt
GOSEC_VERSION=2.14.0
TFSEC_VERSION=0.63.1
KUBESEC_VERSION=2.11.4
KUBE_SCORE_VERSION=1.13.0
DETEKT_VERSION=1.22.0
GITLEAKS_VERSION=7.6.1
SC_VERSION=0.3.3
PMD_VERSION=6.53.0
FSB_VERSION=1.12.0
SB_CONTRIB_VERSION=7.4.7
SB_VERSION=4.7.3
NODE_VERSION=14.5.0
export PATH=$PATH:${APPDIR}/usr/bin:

NODE_TAR=node-v${NODE_VERSION}-linux-${ARCH}.tar.gz

curl -LO "https://nodejs.org/dist/v${NODE_VERSION}/${NODE_TAR}" \
    && tar -C ${APPDIR}/usr/bin/ -xvf ${NODE_TAR} \
    && mv ${APPDIR}/usr/bin/node-v${NODE_VERSION}-linux-${ARCH} ${APPDIR}/usr/bin/nodejs \
    && chmod +x ${APPDIR}/usr/bin/nodejs/bin/node \
    && chmod +x ${APPDIR}/usr/bin/nodejs/bin/npm \
    && rm node-v${NODE_VERSION}-linux-x64.tar.gz

GOSEC_TAR="gosec_${GOSEC_VERSION}_linux_${ARCH}.tar.gz"
curl -LO "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/${GOSEC_TAR}" \
    && tar -C ${APPDIR}/usr/bin/ -xvf ${GOSEC_TAR} \
    && chmod +x ${APPDIR}/usr/bin/gosec \
    && rm ${GOSEC_TAR}

STCHECK_TAR="staticcheck_linux_${ARCH}.tar.gz"
curl -LO "https://github.com/dominikh/go-tools/releases/download/${SC_VERSION}/${STCHECK_TAR}" \
    && tar -C /tmp -xvf ${STCHECK_TAR} \
    && chmod +x /tmp/staticcheck/staticcheck \
    && cp /tmp/staticcheck/staticcheck ${APPDIR}/usr/bin/staticcheck \
    && rm ${STCHECK_TAR}

GLEAKS_TAR="gitleaks-linux-${ARCH}"
TFSEC_TAR="tfsec-linux-${ARCH}"
curl -L "https://github.com/zricethezav/gitleaks/releases/download/v${GITLEAKS_VERSION}/${GLEAKS_TAR}" -o "${APPDIR}/usr/bin/gitleaks" \
    && chmod +x ${APPDIR}/usr/bin/gitleaks \
    && curl -L "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/${TFSEC_TAR}" -o "${APPDIR}/usr/bin/tfsec" \
    && chmod +x ${APPDIR}/usr/bin/tfsec

K8SCORE_TAR="kube-score_${KUBE_SCORE_VERSION}_linux_${ARCH}"
curl -L "https://github.com/zegl/kube-score/releases/download/v${KUBE_SCORE_VERSION}/${K8SCORE_TAR}" -o "${APPDIR}/usr/bin/kube-score" \
    && chmod +x ${APPDIR}/usr/bin/kube-score \
    && wget "https://github.com/pmd/pmd/releases/download/pmd_releases%2F${PMD_VERSION}/pmd-bin-${PMD_VERSION}.zip" \
    && unzip -q pmd-bin-${PMD_VERSION}.zip -d ${OPTDIR}/ \
    && rm pmd-bin-${PMD_VERSION}.zip \
    && mv ${OPTDIR}/pmd-bin-${PMD_VERSION} ${OPTDIR}/pmd-bin

K8SSEC_TAR="kubesec_linux_${ARCH}.tar.gz"
curl -L "https://github.com/detekt/detekt/releases/download/v${DETEKT_VERSION}/detekt-cli-${DETEKT_VERSION}-all.jar" -o "${APPDIR}/usr/bin/detekt-cli.jar" \
    && curl -LO "https://github.com/controlplaneio/kubesec/releases/download/v${KUBESEC_VERSION}/${K8SSEC_TAR}" \
    && tar -C ${APPDIR}/usr/bin/ -xvf ${K8SSEC_TAR} \
    && rm ${K8SSEC_TAR} \
    && curl -LO "https://github.com/spotbugs/spotbugs/releases/download/${SB_VERSION}/spotbugs-${SB_VERSION}.tgz" \
    && file spotbugs-${SB_VERSION}.tgz \
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
