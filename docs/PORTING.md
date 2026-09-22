# 迁移到其他机器

## 1. 先确认 Clash 拓扑

在目标机上准备一份脱敏的拓扑认知：

- 守护器会读取运行时模式：`global` 使用内置 `GLOBAL`，`rule` 使用下方配置的业务入口和选择器；守护器不会修改模式。
- `rule` 模式下检查域名的第一条匹配规则必须指向业务入口组。
- 业务入口最终必须经过一个 `select` 组，再落到物理节点或明确的固定 select 链。
- 所有候选必须是受管理选择器的显式成员。
- `url-test`、`fallback`、`load-balance` 不作为自动切换目标；如确实需要，先转换成由人工确认的 select 适配层。
- `dialer-proxy` 链中的依赖必须在静态配置中完整存在，不能依赖 provider 动态下载、外部插件、证书文件、接口绑定或循环。

不要把完整订阅 YAML 发到公开仓库。只在目标机本地编辑 profile。

## 2. 安装与验证

```bash
git clone https://github.com/Csneer/clash-chatgpt-route-guard.git
cd clash-chatgpt-route-guard
sudo ./install.sh
sudoedit /etc/clash-guard/config.yaml
sudo clash-guard validate
```

`validate` 读取回环控制器、当前 Clash 模式、选择器和候选图，但不会调用 ChatGPT 业务 URL。之后可以明确执行 `clash-guard observe` 和 `clash-guard probe`，确认结果符合目标机实际链路。第一次使用保持守护配置 `mode: observe`。若 Clash Verge 只开放 `external-controller-unix`，请在 Clash YAML 中保留该绝对 socket 路径；守护器会通过本地 Unix HTTP 控制器访问它。

## 3. 接入本地应用证据

若目标机也是 codex-proxy，复制 `config.codex-proxy.example.yaml` 并修正数据库/JSONL 路径、provider 名称和权限。若不是，先实现 adapter，或保持 activity disabled 并只使用手动命令；不要用定时外部健康请求替代 adapter。

确认自动策略后：

```yaml
mode: auto
activity:
  enabled: true
  strategy: faults-only
```

自动 `check` 会在首次配置/路由变化后进入保护期。不要直接复制其他机器的 `state.json`、`pre-switch.yaml.json`、候选评估结果或人工历史。

## 4. 接入订阅更新

本项目不下载订阅。每个供应商应有自己的 adapter，安全契约至少包括：

1. 下载失败、内容为空、格式错误时保持当前配置不变。
2. 先用 Mihomo `-t`、策略校验和规则核对，再安装。
3. 与守护器共用 `mutation_lock`，避免更新和切换并发。
4. 保存当前 select 选择；选中成员消失时停止并要求人工决定。
5. 如果更新必须重启 Mihomo，明确记录这是 updater 的行为，不由 guard 偷偷执行。

## 5. 迁移后的验收

```bash
sudo clash-guard validate
sudo clash-guard observe
sudo clash-guard probe
sudo systemctl start clash-guard.service
journalctl -u clash-guard.service -n 50 --no-pager
```

确认健康/空闲执行的 `check` 没有 `health`、`fault_confirmation`、`candidate` 或 `switched` 外部动作；确认 `clash.service` 和业务服务 PID 未被守护器改变。最后才执行：

```bash
sudo systemctl enable --now clash-guard.timer
```
