# GLOBAL Stable Auto 服务器部署

适用于系统服务管理的 Mihomo：活动配置是一份静态 YAML，通过回环 TCP 或 Unix socket 访问控制器。桌面 Clash Verge 使用 [桌面配置](GLOBAL-AUTO.md)。这里的 `static` 指配置来源，节点仍由自动组动态选择。

## 1. 安装程序与配置

需要 Python 3.8+、PyYAML、curl、systemd 和已运行的 Mihomo。以下示例使用 `/opt/clash/config.yaml`、`/opt/clash/mihomo`、`clash.service`、`127.0.0.1:9090` 控制器及 `127.0.0.1:7890` 业务代理；按目标主机实际路径修改。

```bash
sudo ./install.sh
sudo install -d -m 0700 /var/lib/global-auto
sudo install -m 0600 config/global-auto.system.example.yaml /etc/clash-guard/global-auto.yaml
sudoedit /etc/clash-guard/global-auto.yaml
```

新配置使用 `config_source: static`，不需要 `profile_script`、`profiles_index` 或占位 JS 文件。`controller_tcp` 非空时优先使用指定的回环 `host:port`；若用 Unix socket，设 `controller_tcp: ''`，并填写 `controller_unix` 的绝对路径。认证 secret 从实际 Clash YAML 读取。

状态在目标主机本地积累，不复制其他机器的 `state.json`、评分或节点配置。同一台主机上的订阅更新器、出口绑定器如需共存，应共享 run/mutation/probe 锁；不要启用另一个同时控制 GLOBAL 的守护器。`install.sh` 只安装程序和示例，不启用这些服务。

## 2. 准备自动组

先备份实际 Clash YAML 和当前模式、选择，再在配置中加入 `GLOBAL Stable Auto`。组内每个名称都必须引用 `proxies` 里的普通 SS 节点；支持无插件或内置 obfs，排除 `Codex-*`、dialer 链、接口绑定和其他动态组。候选顺序决定首次未缓存时的初始选择，建议把已验证可用的节点放在第一位。

下面是需要合并到**已有配置**的结构示例，`Node A`、`Node B` 替换成真实节点名。保留原有 `proxies`、其他分组、规则和监听配置：

```yaml
mode: global
profile:
  store-selected: true
proxy-groups:
  # 保留已有分组，并追加：
  - name: GLOBAL Stable Auto
    type: select
    proxies: [Node A, Node B]
    interrupt-exist-connections: false
```

使用目标机器自己的二进制检查配置：

```bash
sudo /opt/clash/mihomo -t -f /opt/clash/config.yaml -d /opt/clash
```

检查通过后，使用现有部署方式热加载；若服务只能重启加载，重启会中断现有连接，安排合适时间执行。加载后核对其他组的选择，再通过已有面板把模式设为 `global`，并选择 `GLOBAL → GLOBAL Stable Auto`。仅修改磁盘 YAML 不会让运行中的核心自动加载，也不会自动把 GLOBAL 选到该组。

没有面板时，可以在目标机器本地运行下列代码，通过实际 YAML 中的回环控制器及 secret 设置模式和选择；设置前确认组已经加载。命令只输出模式与组名：

```bash
sudo python3 - <<'PY'
import sys
sys.path.insert(0, '/usr/local/lib/clash-chatgpt-route-guard')
import global_auto
import mihomo_policy as policy

cfg = global_auto.load_config('/etc/clash-guard/global-auto.yaml')
clash = policy.parse(policy.read(cfg['clash_config']))
api = dict(clash, **{'external-controller': cfg['controller_tcp'],
                    'external-controller-unix': cfg['controller_unix']})
group = cfg['group']
live = policy.api(api, '/proxies')['proxies']
if live.get(group, {}).get('type') != 'Selector':
    raise SystemExit('Load and verify the managed selector first')
policy.api(api, '/proxies/GLOBAL', 'PUT', {'name': group})
policy.api(api, '/configs', 'PATCH', {'mode': 'global'})
snap = global_auto.Auto(cfg).snapshot()
print({key: snap.get(key) for key in ('active', 'mode', 'global_selection', 'selected')})
PY
```

`global-auto` 的 `check` 本身只管理自动组内的选择；模式或 GLOBAL 被人工改走后，它暂停自动探测和切换。后续订阅更新必须保留自动组、候选定义及 `profile.store-selected`，并核对是否需要加载新配置。

## 3. 验证并启动定时服务

始终显式指定服务器配置路径，避免默认读取当前用户的 `~/.config/clash-guard/global-auto.yaml`：

```bash
sudo /usr/local/sbin/global-auto --config /etc/clash-guard/global-auto.yaml status
```

`active: true` 表示实际模式、GLOBAL 选择、候选集合、监听端口和持久选择配置通过核对。status 不进行公网探测；初始库存为空是正常状态。随后启动一次 `check` 会进行真实测量并运行选择策略。

示例系统服务独立命名为 `global-auto-system`，便于区别桌面用户服务。以下命令在仓库根目录执行；若 Mihomo 服务名或安装 PREFIX 不同，先调整 `.service` 的 `After` 和 `ExecStart`：

```bash
sudo install -m 0644 systemd/global-auto-system.service /etc/systemd/system/
sudo install -m 0644 systemd/global-auto-system.timer /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/global-auto-system.service /etc/systemd/system/global-auto-system.timer
sudo systemctl daemon-reload
sudo systemctl start global-auto-system.service
sudo systemctl enable --now global-auto-system.timer
systemctl show global-auto-system.service -p Result -p ExecMainStatus
systemctl is-active global-auto-system.timer
journalctl -u global-auto-system.service -n 20 --no-pager
```

timer 等待时，oneshot service 为 inactive 属于正常状态。确认最近执行 `Result=success`、`ExecMainStatus=0`，状态中的 `tick_at` 持续更新、`pending` 为空，库存开始覆盖本机节点。配置变更后应重新核对状态；出现 pending 时先检查实际选择和日志，不能直接删除它继续切换。

暂停自动管理：

```bash
sudo systemctl disable --now global-auto-system.timer
sudo systemctl stop global-auto-system.service
```

## 4. 验收与恢复

经 7890 做无凭据 HTTPS 请求，确认代理转发工作；HTTP 401/403/405 只证明目标返回了响应，不等于完整业务通过。至少观察几个定时周期，确认模式、选择和 pending 状态。需要故障切换测试时，使用仓库的隔离 Mihomo 测试，避免在生产节点上人为断网。

默认示例每轮结束后 15 秒再次执行，两轮实际转发失败后确认硬故障；有近期可用候选时以约一分钟恢复为目标。候选全部失败、需要更多扫描、锁占用或探测进程异常时恢复会更久，不能承诺固定 60 秒上限。健康主动择优仍要求至少改善 100 ms。

回退部署时先停止本守护服务，使用部署前保存的配置和选择快照恢复 Clash，再验证代理入口。状态、备份、真实订阅和服务器日志留在目标机器，不提交 GitHub。
