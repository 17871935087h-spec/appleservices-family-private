# V2 Linux 到 Windows 设备网关操作说明

本文说明 V2 Linux 服务如何通过 SSH 隧道访问 Windows 上的本机设备网关。这里只记录代码和配置约束；尚未在真实账号、Apple 或服务器上执行连接或验收。

## 连接结构

Windows 上运行两个独立进程：设备 dashboard（默认 `127.0.0.1:18741`）和 V2 gateway（默认 `127.0.0.1:18742`）。Gateway 从本机 dashboard 获取临时 `X-App-Token`，再代理固定的账号查询、家庭读取/变更和设备码 action。V2 Linux 只连接自己的 `127.0.0.1:18742`；SSH 隧道把该连接转到 Windows 主机的 loopback。

两端都使用 Bearer secret。Gateway 只接受 `127.0.0.1` 监听地址，dashboard 也只绑定 IPv4 loopback。不要把任一端口直接绑定到 LAN 或公网，也不要用防火墙端口映射代替 SSH 隧道。

## Windows 设备主机配置

把下列 `V2GATEWAY_*` 环境变量注入 gateway 服务进程。不要把 token 写入启动命令、命令行参数、脚本输出或日志。通过服务管理器可用的受限 secret/environment 配置注入，并限制服务账号对 D 盘目录的访问权限。

| 环境变量 | 值或要求 |
| --- | --- |
| `V2GATEWAY_BEARER_TOKEN` | 随机 secret，至少 32 字节；与 Linux 的 `DEVICE_BRIDGE_TOKEN` 完全一致。代码只从环境读取，不提供 token 命令行参数。 |
| `V2GATEWAY_REGISTRY` | dashboard 生成的 `accounts.json` 绝对路径，例如 `D:\AppleServices\state\accounts.json`。必须解析到 D 盘；不要指向含登录凭据的启动器文件。 |
| `V2GATEWAY_INTENT_DIR` | D 盘上的绝对目录，用于家庭变更 intent 和结果日志；必须在服务重启后保留。 |
| `V2GATEWAY_DASHBOARD_URL` | 可选；默认 `http://127.0.0.1:18741`。只允许同机 IPv4 loopback dashboard。 |
| `V2GATEWAY_LISTEN_ADDR` | 可选；默认 `127.0.0.1:18742`。其他地址会被拒绝。 |

当前仓库提供 `cmd/dashboard` 和 `cmd/v2gateway` 两个可执行入口，但没有 Windows Service 安装器。若由外部服务包装器托管，先启动 dashboard，再启动 gateway；配置 dashboard 的 `-dir` 为 D 盘上的绝对根目录，使其 `accounts.json` 落在 D 盘。Gateway 服务账号必须能读取该文件，并能读写 intent 目录。不要删除或重建 intent 目录来处理状态。

Dashboard 和 gateway 都必须在同一 Windows 主机运行。Dashboard 需要保持可用，且需要读取的设备账号应已登记并在线。首次连接、重新登录或 Apple 要求验证时，由用户在 Windows dashboard/设备端手动完成登录和验证；gateway 不负责账号创建或提交短信验证码，服务运行也不等于 Apple 登录已完成。

Dashboard 启动时会尝试恢复已保存的有效会话，但恢复模式不会把密码放回常驻 worker。用户在 V2 点击添加时，若 V2 已保存目标账号密码，新接口可在校验账号绑定与 worker 能力后经本机或 SSH 隧道交付一次，由目标 worker 为该次操作交给短期 helper；设备网关的 journal、状态文件、日志和响应不得保存或返回密码。没有已保存密码时，仍可使用人工连接后 worker 内存中的密码。Apple 可能要求额外验证；这一恢复及单次传递流程目前仅做离线测试，尚未通过真实账号及跨机验收。

## V2 Linux 配置与 SSH 隧道

V2 进程需要以下环境变量；修改后重启 V2 使其重新读取：

| 环境变量 | 值或要求 |
| --- | --- |
| `DEVICE_BRIDGE_URL` | `http://127.0.0.1:18742`。V2 只接受 HTTP loopback URL。 |
| `DEVICE_BRIDGE_TOKEN` | 与 Windows `V2GATEWAY_BEARER_TOKEN` 相同的 secret。通过 Linux 服务管理器的 secret/environment 机制注入，不写在命令行或日志里。 |

在 V2 Linux 主机上建立 SSH 本地转发，目标地址 `127.0.0.1:18742` 指 Windows 主机上的 gateway：

```sh
ssh -N -L 127.0.0.1:18742:127.0.0.1:18742 <windows-ssh-user>@<windows-host>
```

SSH 会话必须持续运行，并由 V2 的服务管理方式监控和重连。若 V2 位于容器中，隧道的本地 `127.0.0.1:18742` 必须与 V2 进程处于同一网络命名空间。隧道只在 Linux loopback 监听；不要将本地转发改为 `0.0.0.0`。SSH 认证使用已有的 SSH key/agent 等安全配置，不要把 SSH 密码或 Bearer secret 拼进命令。

轮换 Bearer secret 时，同时更新两侧的受限环境配置并重启 gateway 与 V2；否则 V2 会收到未授权响应。不要通过打印环境、进程参数或调试日志来检查 token。

## 账号匹配

`V2GATEWAY_REGISTRY` 必须是 dashboard 维护的 `accounts.json`。`POST /v1/resolve` 会把输入 Apple ID 去除首尾空白并转为小写，然后与 registry 中的 Apple ID 使用相同规则做完整匹配：

- 唯一匹配时返回 registry 的 opaque `account_id`。
- 没有匹配时返回未找到；多个条目匹配时返回冲突，不猜测账号。
- 不做别名、部分匹配或家庭组织者推断。后续账号操作使用 registry 中的精确 `account_id`。

V2 使用其自身的 Apple ID 与设备端精确匹配；设备目录和 registry 文件不需要复制到 V2。V2 已加密保存的目标账号密码只在用户发起添加时按上述方式传递一次，不用来覆盖设备端状态文件。注册表中出现重复 Apple ID 时，需先在本机账号登记数据中消除歧义。

## 重启后的检查

Windows 服务重启后，依次确认 dashboard 与 gateway 进程处于运行状态、dashboard/gateway 端口仍绑定 `127.0.0.1`，并且 gateway 使用原来的 D 盘 registry 和 intent 目录。可在 Windows 主机检查监听地址：

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object { $_.LocalAddress -eq '127.0.0.1' -and $_.LocalPort -in @(18741, 18742) } |
  Select-Object LocalAddress, LocalPort, OwningProcess
```

确认 SSH 隧道已建立后，可从 Linux 做不带 token 的连通性检查：

```sh
curl --max-time 3 -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18742/v1/resolve
```

预期 HTTP 状态为 `401`：它表示请求已到达 gateway，未授权请求被拒绝；这个检查不验证 V2 token，也不访问 Apple。Gateway 没有独立 health endpoint。V2 的桥接状态只表明配置已被加载，不证明隧道可达或 secret 正确。要实际验证账号映射，可在 V2 家庭页选组织者并读取家庭；这个操作会访问 Apple。不要在 shell 命令行中手工传 Bearer secret。

Gateway 重启会从原 intent 目录恢复操作状态。曾处于 `intent` 的变更会恢复为 `outcome_unknown`，该组织者会持续阻断新的家庭写操作。遇到 `outcome_unknown` 时不要重试或删除 journal；先人工核对双方实际状态。当前尚无已验证的解除阻断操作，这种情况仍需人工处置，不能作为生产环境的完整恢复方案。

## 当前边界

- 尚未完成真实跨机或云部署验收；以上步骤是基于当前代码的部署说明。
- 这份说明不承诺固定内存占用、云服务/流量费用为零，也不承诺 Apple 登录免短信、免双重验证或免其他验证。
- 桥接启用后，V2 家庭列表从设备端实时读取，并只显示能唯一匹配到 V2 的账号；未映射成员仅显示数量。邮箱创建能力仍取决于成员自己在 V2 的邮箱登录状态。
- 网关的家庭前检与回读只针对本次组织者和目标账号，不会因读取组织者而触发对整个设备账号池的家庭状态扫描。
- 设备端投影对 Apple 当前返回的、能映射到 registry 的家庭成员逐一校验 `session.json` 与登记 Apple ID；当前成员缺少会话或绑定不一致时阻断读取，不在该家庭的账号缺少会话不会阻断。registry 中重复的账号 ID 或 Apple ID 仍会阻断读取。Apple 返回成员缺少明确 Apple ID、组织者或儿童标记时也会阻断。这些条件尚未通过真实多账号部署验收。
- 含未映射成员的家庭无法确认添加目标不存在；成员移除后如果仍有设备端未映射成员，也不会报告成功。V2 界面更严格：有任何未映射成员时停止添加及移除操作。
- 家庭变更可能耗时数分钟：gateway 的响应超时为 15 分钟、V2 网关客户端为 16 分钟、V2 家庭操作总时限为 24 分钟。中间 SSH、反向代理和服务管理器的限制也需要覆盖实际操作时间；限时中断可能产生结果未知。
- 本机 gateway 只代理固定 action，不暴露 dashboard 原始错误、Cookie 或内部临时 `X-App-Token`。家庭写操作使用一次性 `operation_id`；失败、超时或进程中断后的结果可能为 `outcome_unknown`，不可自动重试。
