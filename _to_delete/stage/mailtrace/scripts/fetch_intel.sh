#!/usr/bin/env bash
# Downloads every offline intel database into ./intel so the forensic path
# runs with no network at demo time. Run once, then again the day before you
# present. Owner: Track D.
#
# Requires MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY in .env
# (free signup: https://www.maxmind.com/en/geolite2/signup)
set -euo pipefail

cd "$(dirname "$0")/.."
[ -f .env ] && set -a && . ./.env && set +a
mkdir -p intel && cd intel

echo "==> MaxMind GeoLite2 (city + ASN)"
# NOTE: the old app/geoip_download?license_key= URL is DEAD. This is the
# current endpoint: HTTP basic auth, and it 302s to Cloudflare R2, so -L
# is mandatory.
if [ -n "${MAXMIND_ACCOUNT_ID:-}" ] && [ -n "${MAXMIND_LICENSE_KEY:-}" ]; then
  for ed in GeoLite2-City GeoLite2-ASN; do
    curl -fSL -u "${MAXMIND_ACCOUNT_ID}:${MAXMIND_LICENSE_KEY}" \
      "https://download.maxmind.com/geoip/databases/${ed}/download?suffix=tar.gz" \
      -o "${ed}.tar.gz"
    tar -xzf "${ed}.tar.gz" --strip-components=1 --wildcards "*/${ed}.mmdb"
    rm -f "${ed}.tar.gz"
    echo "    ${ed}.mmdb ready"
  done
else
  echo "    SKIPPED: set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY in .env"
fi

echo "==> IPinfo Lite (ASN + country, offline mmdb)"
if [ -n "${IPINFO_TOKEN:-}" ]; then
  curl -fSL "https://ipinfo.io/data/ipinfo_lite.mmdb?token=${IPINFO_TOKEN}" \
    -o ipinfo_lite.mmdb
else
  echo "    SKIPPED: set IPINFO_TOKEN in .env (free signup, no card)"
fi

echo "==> Tor exit nodes"
curl -fSL "https://check.torproject.org/torbulkexitlist" -o tor-exits.txt

echo "==> VPN and datacenter ranges (X4BNet, MIT licensed)"
curl -fSL "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt" \
  -o vpn-ipv4.txt
curl -fSL "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt" \
  -o datacenter-ipv4.txt

echo "==> OpenPhish community feed (PhishTank replacement -- registration closed since 2020)"
curl -fSL "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt" \
  -o openphish-feed.txt || echo "    feed unavailable, continuing"

echo
echo "Done. Contents of ./intel:"
ls -lh
echo
echo "Attribution required in your UI/report footer:"
echo "  This product includes GeoLite2 data created by MaxMind (https://www.maxmind.com)"
