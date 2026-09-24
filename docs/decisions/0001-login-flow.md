# 登录流程选择

使用 TapTap 官方 SDK 返回的 MAC 凭证或 OAuth 设备码，服务端通过 TapTap OpenAPI 获取 `openid`、`unionid` 后再建立应用会话。国内与国际区域分别配置 Client ID，并将区域纳入应用身份。

公开 Unity SDK 的普通浏览器登录使用 PKCE 加本机回调 `flow=pc_localhost`。没有把它直接改成服务器回调流程，因为目前证据不能证明 TapTap 接受任意服务器 `redirect_uri`。网页与 PC 无 SDK 场景先采用官方设备码流程；国际设备码地址取自公开 SDK 的区域实现，待真实国际应用验证。

会话采用 24 小时 HS256 JWT，避免把 TapTap 的 `mac_key` 存入服务端。扫码中的设备码只在进程内存保留至过期，因此重启会使未完成的扫码失效；需要多实例时应迁移至共享存储并保持一次性消费。
