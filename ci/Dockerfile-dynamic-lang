FROM registry.access.redhat.com/ubi8/python-38 as builder

ARG CLI_VERSION
ARG BUILD_DATE

ENV TFSEC_VERSION=0.63.1 \
    GITLEAKS_VERSION=7.6.1 \
    KUBESEC_VERSION=2.11.4 \
    KUBE_SCORE_VERSION=1.13.0

USER root

RUN mkdir -p /usr/local/bin/shiftleft \
    && curl -L "https://github.com/zricethezav/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks-linux-amd64" -o "/usr/local/bin/shiftleft/gitleaks" \
    && chmod +x /usr/local/bin/shiftleft/gitleaks \
    && curl -L "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-amd64" -o "/usr/local/bin/shiftleft/tfsec" \
    && chmod +x /usr/local/bin/shiftleft/tfsec \
    && curl -L "https://github.com/zegl/kube-score/releases/download/v${KUBE_SCORE_VERSION}/kube-score_${KUBE_SCORE_VERSION}_linux_amd64" -o "/usr/local/bin/shiftleft/kube-score" \
    && chmod +x /usr/local/bin/shiftleft/kube-score \
    && curl -LO "https://github.com/controlplaneio/kubesec/releases/download/v${KUBESEC_VERSION}/kubesec_linux_amd64.tar.gz" \
    && tar -C /usr/local/bin/shiftleft/ -xvf kubesec_linux_amd64.tar.gz \
    && rm kubesec_linux_amd64.tar.gz

FROM registry.access.redhat.com/ubi8/ubi-minimal as sast-scan-tools

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
      org.label-schema.docker.cmd="docker run --rm -it --name sast-scan shiftleft/scan-slim"

ENV APP_SRC_DIR=/usr/local/src \
    DEPSCAN_CMD="/usr/local/bin/depscan" \
    PMD_CMD="" \
    PYTHONUNBUFFERED=1 \
    NVD_EXCLUDE_TYPES="o,h" \
    PATH=/usr/local/src/:${PATH}:

COPY --from=builder /usr/local/bin/shiftleft /usr/local/bin
COPY tools_config/ /usr/local/src/
COPY requirements.txt /usr/local/src/

USER root

RUN echo -e "[nodejs]\nname=nodejs\nstream=16\nprofiles=\nstate=enabled\n" > /etc/dnf/modules.d/nodejs.module \
    && microdnf install -y gcc python38 python38-devel nodejs git-core which \
    && python3 -m pip install --upgrade pip \
    && pip3 install --no-cache-dir wheel \
    && python3 -m pip install --no-cache-dir -r /usr/local/src/requirements.txt \
    && npm install --no-audit --progress=false --only=production -g @appthreat/cdxgen @microsoft/rush --unsafe-perm \
    && microdnf remove -y gcc python38-devel \
    && microdnf clean all

WORKDIR /app

COPY scan /usr/local/src/
COPY lib /usr/local/src/lib

CMD [ "python3", "/usr/local/src/scan" ]
