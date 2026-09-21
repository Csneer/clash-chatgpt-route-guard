# 本地业务证据

默认适配 codex-proxy 的两个文件。代码只需要时间、provider、错误类别和哈希 request ID；不会查询调用记录的 request/response 正文列。

## 成功记录 SQLite

守护器以只读 URI 打开 SQLite，启用 `query_only`、短锁等待和查询超时保护，执行等价于：

```sql
SELECT completed_at
FROM call_records
WHERE completed_at >= ?
  AND completed_at <= ?
  AND +provider = ?
ORDER BY completed_at DESC
LIMIT 1;
```

`+provider` 是有意的 SQLite 查询规划提示：大型记录库中 provider 单列索引可能扫描大量历史行再排序；已有 completed_at 时间索引更适合最近窗口。项目不会创建索引、运行写操作或修改业务库。

## 错误 JSONL

每行需要有时间字段 `ts`，以及：

```json
{
  "error": {"name": "StreamUpstreamPrematureClose", "message": "..."},
  "context": {
    "provider": "codex",
    "requestId": "...",
    "upstreamStatus": 0
  }
}
```

允许作为自动故障证据的类别是 `StreamUpstreamError`、`StreamUpstreamPrematureClose`、`RequestError` 和 `UpstreamError`，同时必须匹配 provider 和 requestId。网络文本需要明确包含超时、连接重置、TLS 握手失败、EOF 等信号。

以下情况会被过滤：客户端中止/写失败、server error/过载、配额/限流/账号错误、401/403/429/全部 5xx、证书错误、缺 provider、缺 requestId、未知错误文本。

日志读取有大小上限；如果无法覆盖完整时间窗口、JSON 行损坏、文件轮转期间不可读，守护器停止自动外连，而不是退回固定周期探测。部分追加的最后一行会等待下一轮。

## 迁移到其他应用

不能只改两个文件路径就宣称兼容。新应用应提供一个小的本地 adapter，将以下信息映射成上述语义：

1. 最近一次明确成功完成调用的时间和 provider。
2. 网络失败的时间、稳定 request ID、允许的错误类别和可选上游状态。
3. 对不可读、损坏、截断、轮转和查询超时返回明确不可用状态。

不要把“进程存在”“端口打开”或后台定时 ping 当作业务成功证据。
