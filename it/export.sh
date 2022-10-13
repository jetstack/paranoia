#!/usr/bin/env bash
set -euxo pipefail

root_dir="$(dirname "${BASH_SOURCE[0]}")/.."
root_dir="$(realpath "${root_dir}")"
container_tag="container_two_certs"
docker build "${root_dir}/test/container-two-certs" -t "${container_tag}"
docker save "${container_tag}" | paranoia export --output json - > /tmp/paranoia.json

# The container-two-certs image contains the Let's Encrypt X1 root and the DigiCert Global root. Using the test command
# and a bit of bash magic, we verfy that the JSON output has the correct SHA256 fingerprints in the correct places. It
# could only have these fingerprints if it found the certs and exported them correctly.
test "$(jq ".certificates[].fingerprintSHA256" -r /tmp/paranoia.json | sort | head -n1)" = "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161"
test "$(jq ".certificates[].fingerprintSHA256" -r /tmp/paranoia.json | sort | tail -n1)" = "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6"

echo "Pass"
