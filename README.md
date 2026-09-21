# Clash ChatGPT Route Guard

一个保守的 Mihomo/Clash 出口守护方案：它把本机真实业务失败作为自动处理的前提，只在持续的网络类失败出现时，才复核 ChatGPT 兼容接口、隔离评估候选节点，并在满足安全条件后切换受管理的 `select` 组。

核心目标是避免“定时证明自己正常”造成固定外连特征，也避免因为一次 403、429、5xx、客户端取消或机场上游过载就换出口。正常调用和空闲时，systemd timer 只读取本地证据，不访问外部 ChatGPT 接口。

## 特性

- profile 驱动：Clash 配置路径、Mihomo 二进制、业务入口组、受管理选择器、HTTP 监听和检查地址均可替换。
- `faults-only` 活动策略：成功调用不探测；空闲不探测；本地证据源不可读时 fail-closed。
- 至少 3 个新的、不同 request ID 的网络类失败，并跨越最小时间窗口，才开始低频复核。
- `StreamUpstreamPrematureClose` 纳入证据；客户端中止、上游过载、账号/限额、429、全部 5xx、证书错误不作为出口故障依据。
- 所有候选在临时 Mihomo 实例中隔离评估，不挨个切生产选择器；支持固定 `select` 依赖和显式 `dialer-proxy` 链。
- 同出口优先，跨出口需要更长异常跨度并且显式 `allow_cross_ip: true`。
- 切换前后重复检查，配置写入采用 WAL/原子替换；切后业务复测失败只回退一次，无法确认时保留 `pending` 并停止自动切换。
- 手动 `menu`/`use`、`observe`、`probe` 和自动 `check` 入口分离。
- Python 3.6 兼容写法；不读取或持久化调用正文、响应正文、Cookie 或账户凭据。

## 安装

依赖：Linux、systemd、Python 3.6+、PyYAML、curl、可执行的 Mihomo，以及一个只监听回环地址的 HTTP/mixed 业务代理。安装脚本不会启用定时器，也不会覆盖已有 profile。

```bash
git clone https://github.com/Csneer/clash-chatgpt-route-guard.git
cd clash-chatgpt-route-guard
sudo ./install.sh
sudoedit /etc/clash-guard/config.yaml
sudo clash-guard validate
```

初次部署使用 `config/config.example.yaml`；若本机的 codex-proxy 使用仓库文档所述的 SQLite/JSONL 证据格式，可参考 `config/config.codex-proxy.example.yaml`。先使用 `mode: observe`，确认 `validate`、显式 `probe` 和手动 `menu` 均符合预期，再考虑自动模式。

启用自动模式前，必须完成以下替换：

1. `clash_config`、`binary`、`selector`、`entry` 和 `business_proxy`。
2. 检查 URL、预期状态/JSON 字段，以及检查域名在 Clash 规则中确实首先经过 `entry`。
3. `selector` 必须是运行时 `Selector`，候选必须是其显式成员；不要让守护器接管 `url-test`、`fallback` 或 `load-balance`。
4. `activity` 必须指向真实业务证据；不支持的应用格式不要只改路径伪装成兼容。
5. `mode: auto` 和 `activity.enabled: true` 同时使用，并保留 `strategy: faults-only`。

确认后启用：

```bash
sudo systemctl enable --now clash-guard.timer
systemctl status clash-guard.timer --no-pager
clash-guard status
```

安装脚本没有订阅下载器。不同机场的订阅格式、节点协议、转换器和更新时机属于 provider adapter；应在共享 `mutation_lock` 下接入，并先将新配置交给 `mihomo -t` 和 `clash-guard validate`。不要把包含订阅 URL、控制器 secret、节点密码或本机状态的文件放进这个仓库。

## 日常命令

```bash
clash-guard status                 # 本地状态；会读取 Clash 控制器
clash-guard validate               # 只验证当前链路与候选，不做外部业务探测
clash-guard observe                # 明确发起一次业务探测，不切换
clash-guard probe                  # 明确发起隔离候选评估，不切换
clash-guard probe 'candidate-name' # 评估一个候选
clash-guard menu                   # 通用交互菜单
clash-guard use 'candidate-name'   # 预检、确认后安全切换
clash-guard pause                  # 暂停自动变更
clash-guard resume                 # 恢复并进入保护期
```

遇到异常先停守护，不停业务代理：

```bash
sudo systemctl stop clash-guard.timer clash-guard.service
clash-guard status
```

旧的周期探测脚本或旧 timer 不应与本项目并行启用。

## 自动策略的边界

自动处理不是“保证 ChatGPT 永远在线”。未鉴权接口返回预期 401 只证明该接口当时可达，不证明账号、模型权限、额度、完整对话或流式生成。当前实现也无法可靠检测“请求一直挂着但应用尚未写入终止错误”的情况。

固定节点名、组名或叶节点也不保证机场实际出口 IP 固定。同组切换只有在本次故障期内取得新鲜、独立验证的相同出口证据时才优先；未知或变化的 IP 会使证据失效。

自动证据读取针对 codex-proxy 的两个本地格式：`call_records(completed_at, provider)` 和错误 JSONL 的 `ts/error/context`。使用其他业务代理时，请实现等价的本地 evidence adapter；不要读取请求正文来判断健康。

更多设计、迁移和证据格式说明见：

- [设计与安全边界](docs/DESIGN.md)
- [迁移到其他机器](docs/PORTING.md)
- [本地证据适配](docs/EVIDENCE.md)
- [手动与订阅更新集成](docs/INTEGRATION.md)

## 测试

测试只使用临时配置、假控制器和本地 fixture，不会切换线上 Clash。需要 Python 3 和 PyYAML：

```bash
./tests/run.sh
```

真实 Mihomo 集成测试依赖本机二进制、openssl 和可用测试环境；它不应默认连接外部节点，因此可在单独的 CI/测试主机上扩展，不要在生产机上用线上配置做故障注入。

## 安全提醒

本项目会读取活动 YAML 中的控制器 secret 来访问回环控制器，但不会把它输出到日志。状态目录中的 `pre-switch.yaml.json` 可能含节点凭据，必须保持 0700/0600，并加入备份与日志的排除列表。公开仓库只应提交示例和脱敏测试 fixture。
