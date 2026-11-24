#!/bin/bash
set -euo pipefail
umask 077
cd /opt/ig-validation
exec 3>&1
exec >prepare.log 2>&1
trap 'tail -12 prepare.log >&3' ERR
export DEBIAN_FRONTEND=noninteractive
cloud-init status --wait
test "$(dpkg --print-architecture)" = amd64
. /etc/os-release
test "$VERSION_CODENAME" = resolute
# The subnet permits Internet HTTPS, not arbitrary HTTP mirrors.
sed -Ei 's#http://[^/ ]*archive.ubuntu.com/ubuntu#https://archive.ubuntu.com/ubuntu#g;s#http://security.ubuntu.com#https://security.ubuntu.com#g' /etc/apt/sources.list.d/ubuntu.sources
apt-get -o APT::Update::Error-Mode=any update
apt-get -y -o Dpkg::Options::=--force-confold dist-upgrade
apt-get install -y --no-install-recommends docker.io docker-cli mmdebstrap jq ca-certificates curl openssl
systemctl enable --now docker.service

release=$(jq -er .release pins.json)
base="https://github.com/inspektor-gadget/inspektor-gadget/releases/download/$release"
asset="ig-linux-amd64-$release.tar.gz"
for name in "$asset" inspektor-gadget.pub SHA256SUMS SHA256SUMS.bundle; do
    curl --proto '=https' --proto-redir '=https' --retry 3 -fsSL "$base/$name" -o "$name"
done
printf '%s  inspektor-gadget.pub\n' "$(jq -er .release_key_sha256 pins.json)" | sha256sum -c -
jq -er .messageSignature.signature SHA256SUMS.bundle | base64 -d > checksum.sig
openssl dgst -sha256 -verify inspektor-gadget.pub -signature checksum.sig SHA256SUMS
grep -F "  $asset" SHA256SUMS | sha256sum -c -
printf '%s  %s\n' "$(jq -er .archive_sha256 pins.json)" "$asset" | sha256sum -c -
tar xzf "$asset" ig
printf '%s  ig\n' "$(jq -er .ig_sha256 pins.json)" | sha256sum -c -
./ig version | grep -F "$release"

# Construct just the *fixture* rootfs from signed distro packages; never snapshot the host.
# The IG binary and gadget images are upstream release artifacts, not built here.
if ! docker image inspect ig-validation-fixture:1 >/dev/null 2>&1; then
    mmdebstrap --variant=minbase --components=main,universe \
        --include=ca-certificates,python3,openjdk-25-jdk-headless,libh2-java,php8.5-fpm,libfcgi-bin \
        resolute fixture.tar \
        'deb https://archive.ubuntu.com/ubuntu resolute main universe' \
        'deb https://archive.ubuntu.com/ubuntu resolute-updates main universe' \
        'deb https://security.ubuntu.com/ubuntu resolute-security main universe'
    docker import fixture.tar ig-validation-fixture:1
    rm fixture.tar
fi
if test -f /var/run/reboot-required; then echo IG_PREPARED_REBOOT >&3; else echo IG_PREPARED >&3; fi
