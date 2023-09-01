FROM ubuntu:jammy as scan-base

# This section of the multi-stage build is used to build the final Scan image
# We install all building dependencies, run the process of getting and compiling additional tools and then
# use an also ubuntu version in the next stage to only get the obtained tools.
ARG CLI_VERSION
ARG BUILD_DATE
ARG ARCH

ENV GOPATH=/opt/app-root/go \
    GO_VERSION=1.21 \
    PATH=${PATH}:${GOPATH}/bin:/usr/local/go/bin:

LABEL maintainer="qwiet.ai" \
      org.label-schema.schema-version="1.0" \
      org.label-schema.vendor="qwiet.ai" \
      org.label-schema.name="scan-base" \
      org.label-schema.version=$CLI_VERSION \
      org.label-schema.license="GPL-3.0-or-later" \
      org.label-schema.description="Base image containing multiple programming languages" \
      org.label-schema.url="https://qwiet.ai" \
      org.label-schema.usage="https://github.com/ShiftLeftSecurity/sast-scan" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/ShiftLeftSecurity/sast-scan.git" \
      org.label-schema.docker.cmd="docker run --rm -it --name scan-base shiftleft/scan-base /bin/bash"

RUN echo 'APT::Install-Suggests "0";' >> /etc/apt/apt.conf.d/00-docker
RUN echo 'APT::Install-Recommends "0";' >> /etc/apt/apt.conf.d/00-docker

COPY appimage-reqs.sh /
COPY building_env.sh /
COPY dynamic-lang.sh /
COPY requirements.txt /
COPY scan /usr/local/src/
COPY lib /usr/local/src/lib
COPY tools_config/ /usr/local/src/

USER root
# this ensures there will be no pre-deletion of app folder.
ENV KEEP_BUILD_ARTIFACTS=true
ENV ARCH=$ARCH
ENV DEBIAN_FRONTEND=noninteractive

# Dependencies for scan, many of these are only necessary to compile/initialize the tools
RUN apt-get update && apt-get install -y  python3 python3-dev \
        python3-pip python3-setuptools patchelf \
        php php-curl php-zip php-bcmath php-json \
        php-pear php-mbstring php-dev php-xml wget curl git unzip

# Use the same script as we would use locally, for consistency
RUN /appimage-reqs.sh /

# We remove packages that are going to increase the size of our /usr folder.
RUN apt-get remove -y  apache2 python3-dev \
        python3-pip python3-setuptools patchelf desktop-file-utils \
        libgdk-pixbuf2.0-dev wget curl unzip gcc g++ make && apt-get autoremove -y  && apt-get clean -y

FROM ubuntu:jammy as sast-scan-tools

LABEL maintainer="qwiet.ai" \
      org.label-schema.schema-version="1.0" \
      org.label-schema.vendor="qwiet.ai" \
      org.label-schema.name="sast-scan" \
      org.label-schema.version=$CLI_VERSION \
      org.label-schema.license="Apache-2.0" \
      org.label-schema.description="Container with various opensource static analysis security testing tools (shellcheck, gosec, tfsec, gitleaks, ...) for multiple programming languages" \
      org.label-schema.url="https://qwiet.ai" \
      org.label-schema.usage="https://github.com/ShiftLeftSecurity/sast-scan" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/ShiftLeftSecurity/sast-scan.git" \
      org.label-schema.docker.cmd="docker run --rm -it --name sast-scan shiftleft/sast-scan"

# Beware, versions should be kept in sync with appimage-reqs.sh
ENV APP_SRC_DIR=/usr/local/src \
    DEPSCAN_CMD="/usr/local/bin/depscan" \
    MVN_CMD="/usr/bin/mvn" \
    PMD_CMD="/opt/pmd-bin/bin/run.sh pmd" \
    PMD_JAVA_OPTS="--enable-preview" \
    SB_VERSION=4.7.3 \
    PMD_VERSION=6.55.0 \
    SPOTBUGS_HOME=/opt/spotbugs \
    JAVA_HOME=/usr/lib/jvm/jre-11-openjdk \
    SCAN_JAVA_HOME=/usr/lib/jvm/jre-11-openjdk \
    SCAN_JAVA_11_HOME=/usr/lib/jvm/jre-11-openjdk \
    SCAN_JAVA_8_HOME=/usr/lib/jvm/jre-1.8.0 \
    GRADLE_VERSION=7.2 \
    GRADLE_HOME=/opt/gradle \
    GRADLE_CMD=gradle \
    PYTHONUNBUFFERED=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    SHIFTLEFT_HOME=/opt/sl-cli \
    GO111MODULE=auto \
    GOARCH=amd64 \
    GOOS=linux \
    CGO_ENABLED=0 \
    NVD_EXCLUDE_TYPES="o,h" \
    PATH=/usr/local/src/:${PATH}:/opt/gradle/bin:/opt/apache-maven/bin:/usr/local/go/bin:/opt/sl-cli:/opt/phpsast/vendor/bin:

# We only get what we need from the previous stage
COPY --from=scan-base /opt /opt
COPY --from=scan-base /usr /usr

WORKDIR /app

CMD [ "python3", "/usr/local/src/scan" ]
