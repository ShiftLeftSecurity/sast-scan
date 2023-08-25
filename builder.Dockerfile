FROM ubuntu:22.04

# This dockerfile builds a dockerfile that can be used as an env to build the AppImage, beware,it is slow due to IO
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && apt-get install -y python3 python3-dev \
        python3-pip python3-setuptools patchelf desktop-file-utils \
        libgdk-pixbuf2.0-dev php php-curl php-zip php-bcmath php-json \
        php-pear php-mbstring php-dev wget curl git unzip \
        adwaita-icon-theme libfuse2 squashfs-tools zsync

RUN wget https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage && chmod +x appimagetool-x86_64.AppImage && ./appimagetool-x86_64.AppImage --appimage-extract && ln -s /squashfs-root/AppRun /usr/local/bin/appimagetool
RUN wget https://github.com/AppImage/AppImageKit/releases/download/continuous/runtime-x86_64 -O /usr/local/bin/runtime-x86_64 && chmod +x /usr/local/bin/runtime-x86_64
RUN pip3 install git+https://github.com/perrito666/appimage-builder.git

ENV UPDATE_INFO=gh-releases-zsync|ShiftLeftSecurity|sast-scan|latest|*x86_64.AppImage.zsync

WORKDIR /build

ENV PATH="/build/AppDir/usr/bin:/build/AppDir/usr/bin/nodejs/bin:${PATH}"
ENV ARCH=x86_64

CMD mkdir -p appimage-builder-cache && ln -fs /usr/local/bin/runtime-x86_64 appimage-builder-cache && appimage-builder --recipe appimage-builder.yml --skip-test
