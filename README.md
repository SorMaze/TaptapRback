# TapTap Axum 登录后端

此服务支持 TapTap 国内版和国际版的两种登录入口：

1. 游戏客户端使用 TapSDK 登录后，把 `AccessToken` 中的 `kid`、`mac_key` 交给服务端；服务端调用 TapTap OpenAPI 验证并签发自己的会话 JWT。
2. PC 或网页展示二维码，服务端执行 OAuth 2.0 设备码流程，扫码成功后验证资料并签发会话 JWT。

项目不会从客户端提交的 `openid` 直接建立会话。`openid`、`unionid` 均以 TapTap OpenAPI 的响应为准。

## 登录网页

启动服务后打开 `http://127.0.0.1:3000/`。Axum 同源提供页面、样式、脚本和登录 API。页面会按服务器配置显示可选区域，自动生成扫码二维码，遵守 TapTap 返回的轮询间隔，授权后再调用 `/auth/me` 校验游戏会话。登录会话保存在当前浏览器标签的 `sessionStorage` 中；“清除本地会话”只清除浏览器里的令牌，不撤销已签发的 JWT。部署到公网时应通过 HTTPS 反向代理提供服务。

## 启动

配置至少一个区域的 Client ID，以及随机的会话密钥：

```powershell
$env:TAPTAP_CN_CLIENT_ID = "国内应用的 Client ID"
$env:TAPTAP_GLOBAL_CLIENT_ID = "国际应用的 Client ID"
$env:SESSION_SECRET = "至少 32 字节的随机字符串，生产环境请安全保存"
$env:BIND_ADDR = "127.0.0.1:3000"
cargo run
```

国内和国际应用的 Client ID 分开配置；只接入一个区域时可省略另一个。默认仅监听本机；部署时由 HTTPS 反向代理对外提供服务。`SESSION_SECRET` 改变后旧会话会失效。

## HTTP API

### TapSDK 客户端登录

`POST /auth/taptap/sdk`

```json
{
  "region": "cn",
  "access_token": {
    "kid": "SDK 返回的 kid",
    "mac_key": "SDK 返回的 mac_key",
    "mac_algorithm": "hmac-sha-1"
  },
  "scopes": ["public_profile"]
}
```

`region` 为 `cn` 或 `global`。需要昵称和头像时传 `public_profile`；只申请 `basic_info` 时传 `basic_info`，服务端将调用基础信息接口。实际权限由 TapTap 校验，客户端声明的 scope 不会绕过 TapTap 的授权检查。提交凭证前，客户端应调用 SDK 的 `GetCurrentTapAccount` 获取最新值。此接口只应通过 HTTPS 使用，不要记录请求体中的 `mac_key`。

成功返回 `session_token`、`expires_in`、`region` 和经 TapTap 验证的 `user`。会话令牌是有效期 24 小时的 HS256 JWT，供本服务的受保护接口使用；它不是 TapTap 的 Access Token。

### 扫码登录

1. `POST /auth/taptap/device`，请求体为 `{"region":"cn"}` 或 `{"region":"global"}`。返回 `flow_id`、`qrcode_url`、`qr_image`（服务端生成的 SVG data URL）、`expires_in`、`interval`。前端显示 `qr_image`。
2. `POST /auth/taptap/device/{flow_id}/poll`。未授权时返回 HTTP 202，`{"status":"pending","retry_after":秒数}`；按 `retry_after` 等待后重试。
3. 授权成功时返回 HTTP 200，`{"status":"complete","login":{...}}`。同一个 `flow_id` 只能成功消费一次。过期返回 HTTP 410。

服务器保存 `device_code`，不把它交给前端。流程状态目前保存在进程内存中，服务重启后未完成的扫码流程失效；多实例部署需要把流程状态迁移到共享存储。

### 会话检查

`GET /auth/me`，请求头 `Authorization: Bearer <session_token>`，返回 JWT 中的 `sub`（`openid`）、`region` 和过期时间。业务数据库应使用 `(region, openid)` 作为用户身份键，避免跨区域混淆。此服务目前没有账号持久化、会话撤销或绑定其他平台账号的功能。

`GET /health` 返回 `ok`。

## SDK 协议核对

基于 TapTap 官方 [v4 国内登录文档](https://developer.taptap.cn/docs/sdk/taptap-login/guide/)、[国内设备码文档](https://developer.taptap.cn/docs/sdk/taptap-login/device-code/)、[v4 国际登录文档](https://developer.taptap.io/docs/sdk/taptap-login/guide/) 和 [国际 OAuth API 文档](https://developer.taptap.io/docs/sdk/taptap-login/taptap-oauth/)；同时检查了 TapTap 公开的 Unity SDK 源码（仓库快照 `668e044`）：

- [`Region.cs`](https://github.com/taptap/TapSDKLogin-Unity/blob/668e044/Runtime/Internal/Region.cs)：国内授权与 OpenAPI 域名为 `accounts.tapapis.cn` / `open.tapapis.cn`；国际版为 `accounts.tapapis.com` / `open.tapapis.com`。
- [`LoginService.cs`](https://github.com/taptap/TapSDKLogin-Unity/blob/668e044/Standalone/Runtime/Internal2/LoginService.cs)：设备码申请、`device_token` 轮询，以及 MAC 头的格式和规范化签名串。
- [`WebLoginRequestManager.cs`](https://github.com/taptap/TapSDKLogin-Unity/blob/668e044/Standalone/Runtime/Internal/WebLoginRequestManager.cs)：SDK 的浏览器登录走带 PKCE 的本机回调（`flow=pc_localhost`），不是把网页回调直接转给游戏后端。因此本服务使用 SDK 凭证提交或设备码模式，没有假设任意服务器回调地址都被 TapTap 接受。

MAC 签名串是 `timestamp\nnonce\nmethod\nuri\nhost\nport\n\n`，使用授权所得的 `mac_key` 按 `mac_algorithm` 做 HMAC，再 Base64 编码。文档常见的算法是 HMAC-SHA1；公开 SDK 还支持 HMAC-SHA256，本服务兼容这两种。签算时包含完整查询字符串。国际版设备码域名是公开 SDK 源码中的实现；它在当前测试中由模拟上游覆盖，尚需国际版应用凭证做真实账号验证。

## 验证

运行 `cargo test` 和 `cargo clippy --all-targets -- -D warnings`。测试包含独立 HMAC 样例、模拟 TapTap OpenAPI 的 SDK 登录、设备码待授权到成功、会话验证和流程单次消费。

2026-09-23 使用用户提供的国内版 Client ID 完成了一次真实设备码登录：TapTap 返回二维码，扫码后 token 轮询成功，MAC 签名请求获取到 `openid` / `unionid`，应用签发的会话通过 `/auth/me`，重复消费流程返回 404。测试账号标识和会话令牌未写入仓库。国际版路径按官方 SDK 区域实现接入，尚未使用国际版应用做真实账号验收。

同日还在 Axum 提供的网页上完成真实扫码登录，浏览器显示“游戏登录成功”，成功页使用服务端验证后的玩家资料。头像地址在测试浏览器无法加载时，页面自动隐藏破图；刷新后 `/auth/me` 再次校验会话，玩家名称与区域正确恢复。测试时服务监听 `127.0.0.1:3000`，`/health` 返回 HTTP 200。

## 许可证

本项目采用 [BSD 2-Clause 许可证](LICENSE)。Copyright 2026 SorMaze。
