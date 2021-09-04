FROM python:3.9

LABEL maintainer="ShiftLeftSecurity" \
      org.label-schema.schema-version="1.0" \
      org.label-schema.vendor="shiftleft" \
      org.label-schema.name="store-api" \
      org.label-schema.version="1.0.0" \
      org.label-schema.license="UNLICENSED" \
      org.label-schema.description="API to store and retrieve AppThreat reports" \
      org.label-schema.url="https://www.shiftleft.io" \
      org.label-schema.usage="https://github.com/ShiftLeftSecurity/sast-scan" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/ShiftLeftSecurity/sast-scan.git" \
      org.label-schema.docker.cmd="docker run --rm -it --name store-api shiftleft/store-api"

USER root
WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

ENV QUART_ENV=production \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY . /app/
CMD [ "python", "app.py" ]
