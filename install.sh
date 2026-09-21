#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo 'install.sh must run as root' >&2
  exit 1
fi

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
lib_dir=/usr/local/lib/clash-chatgpt-route-guard
config_dir=/etc/clash-guard
state_dir=/var/lib/clash-guard

install -d -m 0755 "$lib_dir" "$config_dir" "$state_dir" /usr/local/sbin /run/lock
install -m 0644 "$root_dir/src/clash_guard.py" "$lib_dir/clash_guard.py"
install -m 0644 "$root_dir/src/clash_demand.py" "$lib_dir/clash_demand.py"
install -m 0644 "$root_dir/src/clash_common.py" "$lib_dir/clash_common.py"
install -m 0644 "$root_dir/src/mihomo_policy.py" "$lib_dir/mihomo_policy.py"
install -m 0755 "$root_dir/bin/clash-guard" /usr/local/sbin/clash-guard
install -m 0644 "$root_dir/systemd/clash-guard.service" /etc/systemd/system/clash-guard.service
install -m 0644 "$root_dir/systemd/clash-guard.timer" /etc/systemd/system/clash-guard.timer

if [[ ! -e "$config_dir/config.yaml" ]]; then
  install -m 0600 "$root_dir/config/config.example.yaml" "$config_dir/config.yaml"
  echo "Created template $config_dir/config.yaml; edit it before enabling the timer."
else
  echo "Preserved existing $config_dir/config.yaml"
fi
install -m 0600 "$root_dir/config/config.example.yaml" "$config_dir/config.example.yaml"
install -m 0600 "$root_dir/config/config.codex-proxy.example.yaml" "$config_dir/config.codex-proxy.example.yaml"

if command -v systemctl >/dev/null 2>&1; then
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
