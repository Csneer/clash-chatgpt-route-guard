#!/usr/bin/env bash
set -euo pipefail

destdir=${DESTDIR:-}

if [[ -z "$destdir" && "$(id -u)" -ne 0 ]]; then
  echo 'install.sh must run as root' >&2
  exit 1
fi

if [[ -n "$destdir" && "$destdir" != /* ]]; then
  echo 'DESTDIR must be an absolute path' >&2
  exit 1
fi

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
lib_dir=${PREFIX:-/usr/local}/lib/clash-chatgpt-route-guard
config_dir=/etc/clash-guard
state_dir=/var/lib/clash-guard

target() {
  printf '%s%s' "$destdir" "$1"
}

install -d -m 0755 "$(target "$lib_dir")" "$(target "$config_dir")" "$(target "$state_dir")" "$(target "${PREFIX:-/usr/local}/sbin")" "$(target /run/lock)" "$(target /etc/systemd/system)"
install -m 0644 "$root_dir/src/clash_guard.py" "$(target "$lib_dir")/clash_guard.py"
install -m 0644 "$root_dir/src/clash_demand.py" "$(target "$lib_dir")/clash_demand.py"
install -m 0644 "$root_dir/src/clash_common.py" "$(target "$lib_dir")/clash_common.py"
install -m 0644 "$root_dir/src/mihomo_manualize.py" "$(target "$lib_dir")/mihomo_manualize.py"
install -m 0644 "$root_dir/src/mihomo_policy.py" "$(target "$lib_dir")/mihomo_policy.py"
install -m 0755 "$root_dir/bin/clash-guard" "$(target "${PREFIX:-/usr/local}/sbin")/clash-guard"
install -m 0755 "$root_dir/bin/mihomo-manualize" "$(target "${PREFIX:-/usr/local}/sbin")/mihomo-manualize"
service_file=$(mktemp)
trap 'rm -f "$service_file"' EXIT
sed "s#^ExecStart=.*#ExecStart=${PREFIX:-/usr/local}/sbin/clash-guard check#" \
  "$root_dir/systemd/clash-guard.service" >"$service_file"
install -m 0644 "$service_file" "$(target /etc/systemd/system)/clash-guard.service"
install -m 0644 "$root_dir/systemd/clash-guard.timer" "$(target /etc/systemd/system)/clash-guard.timer"

if [[ ! -e "$(target "$config_dir/config.yaml")" ]]; then
  install -m 0600 "$root_dir/config/config.example.yaml" "$(target "$config_dir")/config.yaml"
  echo "Created template $config_dir/config.yaml; edit it before enabling the timer."
else
  echo "Preserved existing $config_dir/config.yaml"
fi
install -m 0600 "$root_dir/config/config.example.yaml" "$(target "$config_dir")/config.example.yaml"
install -m 0600 "$root_dir/config/config.codex-proxy.example.yaml" "$(target "$config_dir")/config.codex-proxy.example.yaml"

if [[ -z "$destdir" ]] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi

cat <<'NOTICE'
Installation complete. The timer was not enabled or started.

Next steps:
  1. Edit /etc/clash-guard/config.yaml and keep mode: observe initially.
  2. Run: clash-guard validate
  3. Run an explicit isolated check: clash-guard probe
  4. After local evidence paths and route names are verified, set mode: auto,
     keep activity.strategy: faults-only, then enable clash-guard.timer.
NOTICE
