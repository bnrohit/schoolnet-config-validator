#!/usr/bin/env bash
set -euo pipefail

echo "Checking NGINX image pins..."
bad=0
while IFS= read -r -d '' file; do
  while IFS= read -r line; do
    tag="$(sed -E 's/^[[:space:]]*FROM[[:space:]]+nginx:([^[:space:]]+).*/\1/I' <<<"$line")"
    ver="$(sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/' <<<"$tag")"
    if [[ ! "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "ERROR: $file uses an unpinned/unrecognized NGINX tag: $tag"
      bad=1
      continue
    fi
    IFS=. read -r major minor patch <<<"$ver"
    if (( major < 1 )); then
      echo "ERROR: $file pins unsupported NGINX $ver."
      bad=1
    elif (( major == 1 )); then
      if (( minor < 30 )); then
        echo "ERROR: $file pins NGINX $ver; require >=1.30.6 stable (or >=1.31.7 mainline)."
        bad=1
      elif (( minor == 30 && patch < 6 )); then
        echo "ERROR: $file pins NGINX $ver; require >=1.30.6."
        bad=1
      elif (( minor == 31 && patch < 7 )); then
        echo "ERROR: $file pins NGINX $ver; require >=1.31.7."
        bad=1
      fi
    fi
  done < <(grep -Eih '^[[:space:]]*FROM[[:space:]]+nginx:' "$file" || true)
done < <(find . -type f \( -name 'Dockerfile' -o -name 'Dockerfile.*' \) -not -path './.git/*' -print0)

echo "Checking for mDNS/Bonjour/ZeroConf runtime enablement..."
if find . -type f \
    \( -name 'Dockerfile*' -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' \
       -o -name 'compose.yml' -o -name 'compose.yaml' -o -name '*.service' -o -name '*.socket' \
       -o -name '*.conf' -o -name 'requirements*.txt' -o -name 'package*.json' \
       -o -name '*.py' -o -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' -o -name '*.tsx' \) \
    -not -path './.git/*' -not -path '*/node_modules/*' -print0 \
  | xargs -0 -r grep -EinH 'avahi(-daemon|-utils)?|mdns-repeater|(^|[^[:alnum:]_])(mDNS|mdns|zeroconf|bonjour)([^[:alnum:]_]|$)|5353[/: ]*(udp)?|udp[/: ]*5353'; then
  echo "ERROR: mDNS/Bonjour/ZeroConf runtime reference detected. Review and remove/disable it."
  bad=1
fi

if (( bad != 0 )); then
  exit 1
fi

echo "Network service security baseline passed."
