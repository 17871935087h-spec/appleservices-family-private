# App 专用密码

设备面板提供“App 专用密码”卡片；V2 的 Apple 账号详情也提供同一入口。选择账号后，可读取列表、明确授权连接管理会话、新建带标签的密码、复制或隐藏密码，以及恢复最近生成结果。

Windows dashboard 接口为 `POST /api/app-passwords/{status,connect,create,result,review}?account=<id>`，使用原有 `X-App-Token`。V2 gateway 接口为 `POST /v1/app-passwords/{status,connect,create,result,review}`，沿用 Bearer、loopback 和账号唯一绑定校验；请求另带 `account_id` 与 `apple_id`。

- `status`：仅检查已有管理会话并读取列表，不加载主密码或触发登录。
- `connect`：必须同时明确提供 `allow_web_login=true` 和 `allow_device_verification=true`，才可使用此账号保存的密码和当前设备验证码。验证码不返回浏览器，不发送短信。
- `create`：提供不超过 64 个字符的 `description`、小写 UUID `request_id` 和显式 `allow_password_challenge`。仅在已知普通主密码复核分支允许复核并重发一次；额外验证、条款及风控会停止操作。
- `result`：使用最近成功请求的 `request_id` 显式恢复密码。列表和状态响应不返回密码。
- `review`：用户核对未知结果后，以原 `request_id` 确认解除本地阻挡；服务器必须再次成功读取列表。此操作不登录、不创建或撤销密码，旧请求编号仍不能重放。

管理会话、操作编号和最近结果分别保存为账号目录的 `app-password-session.dpapi`、`app-password-intent.dpapi`、`app-password-result.dpapi`。它们绑定 Apple ID、用途及 Windows 服务用户，并与原 `credential.dpapi` 分开。部署后必须沿用原服务身份；不能把这些文件移交另一用户直接解密。

生成前先持久化意图。同一请求编号不会重复生成；未确认的提交在服务重启后仍会阻挡新生成。只有最近成功结果可恢复，较早密码仍需由使用者自行保存。更改 Apple 主密码等官方操作可能使专用密码失效。

本功能以合成 HTTP 响应验证协议、认证边界、并发和崩溃恢复；部署检查只读取无管理会话账号的本地状态。真实 Apple 登录及专用密码生成需用户在前台明确发起。
