#!/bin/sh
# Reject markers of the reference project and committed key material.
# The new repository must contain only fictional example values.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

excludes="--exclude-dir=.git --exclude-dir=dist --exclude-dir=__pycache__"
excludes="$excludes --exclude-dir=certs --exclude=audit-values.sh"

status=0

if grep -RIniE $excludes \
    'agrd|adguard|spiffe|spire|workload[_-]api|jwt[_-]svid|svid|ebala|bit\.int' .; then
  echo "FAIL: a reference-project identifier remains" >&2
  status=1
fi

if grep -RInE $excludes 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' .; then
  echo "FAIL: committed private key material" >&2
  status=1
fi

key_files=$(find . -path ./.git -prune -o -type f \
  \( -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '*.csr' \
     -o -name '*.srl' \) -print)
if [ -n "$key_files" ]; then
  echo "FAIL: committed certificate or key file:" >&2
  echo "$key_files" >&2
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "PASS: no reference identifiers or committed key material"
fi
exit "$status"
