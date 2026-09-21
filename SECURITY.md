# Security policy

## Reporting

Please do not publish credentials, subscription URLs, controller secrets,
node passwords, request bodies, account identifiers, or production IPs in an
issue. For a private report, contact the repository owner through GitHub.

## Deployment rules

- Keep `/etc/clash-guard/config.yaml` at mode 0600 when it contains a
  controller secret or local paths.
- Keep the state directory at mode 0700; `pre-switch.yaml.json` can contain
  the full previous proxy configuration.
- Do not copy `state.json`, `evaluation.json`, `probe.json`, SQLite files or
  application logs into this repository.
- Use a loopback-only Mihomo controller. The guard refuses non-loopback
  controller addresses.
- Start in `mode: observe`, validate the route, and test on an isolated
  configuration before enabling automatic changes.
