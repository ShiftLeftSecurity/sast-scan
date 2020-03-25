#!/bin/sh
#
# An example pre-commit hook to perform sast-scan on the repo.
# Copy this file to .git/hooks/pre-commit
echo '

 █████╗ ██████╗ ██████╗ ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
███████║██████╔╝██████╔╝   ██║   ███████║██████╔╝█████╗  ███████║   ██║
██╔══██║██╔═══╝ ██╔═══╝    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
██║  ██║██║     ██║        ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
╚═╝  ╚═╝╚═╝     ╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝

'
docker_state=$(docker info >/dev/null 2>&1)
if [[ $? -ne 0 ]]; then
    echo "Docker does not seem to be running, please start the service or run the desktop application"
    exit 1
fi
docker pull shiftleft/sast-scan >/dev/null 2>&1

# Scan credentials using gitleaks
docker run --rm --tmpfs /tmp -e "WORKSPACE=${PWD}" -v $PWD:/app shiftleft/sast-scan gitleaks --uncommitted --repo-path=/app --pretty

if [ $? == 1 ]; then
	echo "Remove the credentials identified by the scan"
    exit 1
fi

# Perform automatic scan
echo "Performing SAST scan on the repo"
docker run --rm --tmpfs /tmp -e "WORKSPACE=${PWD}" -v $PWD:/app shiftleft/sast-scan scan --src /app --out_dir /app/reports
