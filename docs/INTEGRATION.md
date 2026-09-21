# 手动操作与订阅更新集成

## 手动切换

守护器的 `menu` 和 `use` 是 profile-driven 的通用入口：它们读取当前受管理 selector 的实际成员，重新预检目标，要求交互确认，并使用与自动切换相同的事务和回退逻辑。

它们不会自动修改所有地区组，也不会把当前机器的机场命名规则推广到其他机器。目标必须已经存在于 selector 的显式成员列表中。

## 手动选择器

`clash-guard menu/use` 是 profile-driven 的通用手动入口，不依赖具体的机场地区命名，也不把订阅转换逻辑硬编码进守护器。跨供应商时只需让 profile 的 `selector`、`entry`、候选配置和业务检查与目标机一致。

## 更新器契约

更新器可以继续由供应商/机器维护，但必须：

- 使用 `/run/lock/clash-config-update.lock`（或 profile 中相同的 `mutation_lock`）。
- 下载和转换全部在临时文件中完成。
- 通过 Mihomo 配置测试和规则/选择保护后再原子替换。
- 不在仓库、systemd unit、日志中写入订阅 URL 或 secret。
- 失败时保留原配置；若重启 Clash 失败，使用自己的备份回退并重新验证运行时规则。

guard 本身不会运行更新器，也不会因为更新器失败自动换节点。

## 与旧自动监控并存

不要启用旧的周期健康监控 timer。只保留一个管理同一 selector 的 guard 和一个共享锁的 updater；多个 watcher 会造成重复探测、竞争写入和不必要的出口变化。
