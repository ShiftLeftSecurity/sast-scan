#!/bin/sh
#
# An example pre-commit hook to perform sast-scan on the repo.
# Copy this file to .git/hooks/pre-commit
echo '
  ___            _____ _                    _
 / _ \          |_   _| |                  | |
/ /_\ \_ __  _ __ | | | |__  _ __ ___  __ _| |_
|  _  | '_ \| '_ \| | | '_ \| '__/ _ \/ _` | __|
| | | | |_) | |_) | | | | | | | |  __/ (_| | |_
\_| |_/ .__/| .__/\_/ |_| |_|_|  \___|\__,_|\__|
      | |   | |
      |_|   |_|
'
docker_state=$(docker info >/dev/null 2>&1)
if [[ $? -ne 0 ]]; then
    echo "Docker does not seem to be running, please start the service or run the desktop application"
    exit 1
fi
docker pull quay.io/appthreat/sast-scan >/dev/null 2>&1

# Scan credentials using gitleaks
docker run --rm --tmpfs /tmp -e "WORKSPACE=${PWD}" -v $PWD:/app quay.io/appthreat/sast-scan gitleaks --uncommitted --repo-path=/app

if [ $? == 1 ]; then
	echo "Remove the credentials identified by the scan"
    exit 1
fi

# Perform automatic scan
echo "Performing SAST scan on the repo"
docker run --rm --tmpfs /tmp -e "WORKSPACE=${PWD}" -v $PWD:/app quay.io/appthreat/sast-scan scan --src /app --out_dir /app/reports
