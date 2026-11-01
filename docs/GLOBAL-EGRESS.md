# GLOBAL 自动出口绑定

`global-egress-lock` 是可选的 Clash Verge 用户服务。开启后，在 GLOBAL 中选择一个新节点，服务会等待选择稳定，解析该节点的后端入口，在隔离 Mihomo 中验证各入口，随后固定一个多次采样公网 IP 一致的入口。它保持用户选中的节点，不自行切换 GLOBAL 到另一节点。

例如 `GLOBAL → Node A → pool.example` 原先可能随 DNS 解析使用不同后端。绑定后成为 `GLOBAL → Node A → 已验证入口 IP`。公网出口可能与这个入口 IP 不同。切到 Node B 时自动为 B 建立自己的绑定；再次选择 A 时复用 A 的绑定，并要求采样仍匹配 A 原来记录的公网 IP。

## 行为与边界

- 5 秒本地轮询，选择稳定至少 5 秒后开始采样。采样耗时取决于入口数和网络，切节点后到绑定完成前存在短暂未固定窗口。
- 默认每个入口进行 3 轮、每轮 2 个 HTTPS IP 查询。所有样本成功且一致才合格。若实际连接已经使用一个合格入口，优先保留它；否则比较采样耗时。
- 没有到期轮换。健康绑定长期保留；每 15 分钟核验当前出口。核验失败保留固定入口并在 journal 报告，不自动寻找不同公网 IP。
- 新节点采样失败至少冷却 10 分钟，用户再次选择别的节点可开始新一轮。rule/direct 模式不建立新绑定。
- 当前支持直接 Shadowsocks（无插件或内置 obfs）、非 TLS 的直接 SOCKS5，以及到这些节点的静态 select 组。动态 fallback/url-test/load-balance、dialer 链和其他需要专门 SNI 处理的协议明确拒绝绑定。
- 绑定记录写入当前订阅 JS。节点同名但原始域名、类型或端口改变时，不盲目套用旧入口。凭据/传输定义变化时自动操作停止，等待核查。
- 修改对象是共享节点定义：该节点在 rule 模式被引用时也使用固定入口。停止 timer 只暂停新绑定及核验，已有固定记录继续生效。
- 固定入口能消除 DNS 多后端轮换，无法阻止供应商在同一入口内部更换公网 NAT 地址。不同节点也不保证共享同一公网 IP。WAF、Cookie、账号或业务挑战可能独立发生。

## 用户服务安装

依赖 Python 3.8+、PyYAML、curl、Node.js，以及 Mihomo。将 `src/global_egress.py`、`src/clash_common.py`、`src/mihomo_policy.py` 安装到用户私有程序目录，设置 `bin/global-egress-lock` 中使用的 `CLASH_GUARD_LIB`，或使用等价的绝对路径启动器。把 `config/global-egress.example.yaml` 复制为 `~/.config/clash-guard/global-egress.yaml` 并填写路径。`profiles_index` 用来核验活动订阅和查回旧绑定的原始域名。

`state_dir` 应为 0700；状态、备份和锁不得进入公开仓库。配置改写前会保存 0600 备份，使用 Mihomo 配置验证和 Node 执行级输出对照。只有 server 发生变化才热加载，不重启代理、不删除现有连接。旧 TCP 连接可能保留之前的入口，直到应用自然重连。

将 `systemd/global-egress-lock.{service,timer}` 安装到 `~/.config/systemd/user/`，确认 ExecStart 指向实际启动器，然后：

```bash
systemd-analyze --user verify ~/.config/systemd/user/global-egress-lock.service
systemctl --user daemon-reload
systemctl --user enable --now global-egress-lock.timer
```

这组用户服务独立于 `clash-guard.timer`。不要同时启用会自动更换 GLOBAL 的其他守护器。脚本与外部订阅更新器应共享 mutation lock；GUI 不会遵循这个锁，因此提交前后还会核验选路、配置和脚本版本，不能将文件原子替换理解为跨进程事务。

## 操作

```bash
global-egress-lock status       # 本地状态、当前选择和活跃连接入口；不访问公网
global-egress-lock verify       # 只读公网出口核验；失败返回非零
global-egress-lock bind-now     # 明确立即检测并绑定当前 GLOBAL 节点
global-egress-lock check        # 定时服务使用：自动检测、采样、持久绑定
systemctl --user enable --now global-egress-lock.timer  # 开启
systemctl --user disable --now global-egress-lock.timer # 暂停后续轮次
systemctl --user stop global-egress-lock.service       # 同时结束正在执行的轮次
journalctl --user -u global-egress-lock.service -n 30 --no-pager
```

`status` 的 `binding.public_ip` 是绑定时验证过的出口；`verify` 给出新的实测。`pending` 非空表示提交或加载结果尚未确认，服务会拒绝继续写入；核对该状态指向的备份、实际配置和当前选择后再处理，不能仅清空 pending 掩盖问题。

需要恢复订阅原本的 DNS 轮转时，应先停服务，再从受管理 JS 块移除目标节点条目，并将运行节点的 server 恢复到记录的 origin，经配置验证后热加载。此操作会改变新连接出口，不应当作日常“暂停”执行。

测试用临时文件、假控制器以及本机隔离 Mihomo 验证绑定流程，不通过切换生产 GLOBAL 演示功能。
