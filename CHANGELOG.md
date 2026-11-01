# Changelog

## v0.1.0 — 2026-11-01

首次为现有工具集发布版本，采用 MIT 许可证。

- `clash-guard`：依据持续业务网络错误进行隔离候选探测、路由切换和失败回退，支持 GLOBAL / rule 模式。
- `global-auto`：为 Clash Verge 和系统 Mihomo 提供 GLOBAL 节点可用性、延迟评估及自动选择。
- `global-egress-lock`：跟随手动选择固定已验证的节点入口，并持久保存出口绑定。
- 提供配置示例、安装脚本、systemd 模板及桌面和服务器部署说明。
- 新增 GitHub Actions，运行单元测试、固定 Mihomo 版本的原生集成测试和隔离安装检查。

安装条件、验证范围和升级注意事项见 [v0.1.0 发行说明](docs/releases/v0.1.0.md)。
