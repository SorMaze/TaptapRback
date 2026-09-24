# 网页跳转登录流程

手机浏览器访问登录页时，扫码不是可用的交互。本服务按两级方案支持移动端网页授权。

## 设备码跳转（默认，已验证流程）

设备码接口返回的 `qrcode_url` 本身就是 TapTap 授权页地址。手机浏览器不展示二维码，改为在当前标签页打开 `qrcode_url`，由 TapTap 页面引导登录并唤起已安装的 TapTap 客户端确认授权；本页面保留 `flow_id` 并继续轮询 `/poll`，返回时通过 `visibilitychange` 立即补一次轮询。该路径完全复用已验证的设备码协议，无任何新的协议假设。

## 授权码 + PKCE 跳转（配置 `PUBLIC_BASE_URL` 后启用）

公开 Unity SDK（快照 `668e044`）的浏览器登录使用 `https://accounts.taptap.cn/authorize`（国际为 `https://www.taptapauth.com/authorize`），参数为 `client_id`、`response_type=code`、`redirect_uri`、`state`、`code_challenge`、`code_challenge_method=S256`、`scope`，换 token 走 `POST /oauth2/v1/token`、`grant_type=authorization_code` 加 `code_verifier`。本服务按同样参数实现服务端回调流程：`code_verifier` 与 `state` 仅存服务端内存，回调成功后将应用会话写入浏览器 `sessionStorage` 并跳回首页。

风险与 0001 相同：SDK 只使用 loopback 与自定义 scheme 作为 `redirect_uri`，没有官方文档证明 TapTap 接受任意服务器回调地址；SDK 的 `flow=pc_localhost` 参数为本流程省略。因此该路径上线前必须用真实应用凭证验证授权页是否接受配置的 `redirect_uri`；若被拒绝，手机端自动回退到设备码跳转模式（不配置 `PUBLIC_BASE_URL` 即为该行为）。

2026-09-24 使用用户提供的国内版 Client ID 完成真实验证：浏览器打开 `accounts.taptap.cn/authorize` 授权链接（`redirect_uri` 为 `http://127.0.0.1:3000` 的本服务回调），TapTap 接受该回调地址并在授权后带回 `code` 与 `state`；服务端用 PKCE `code_verifier` 换得 MAC 凭证、拉取资料并签发会话，浏览器显示"游戏登录成功"。同一 `state` 重复回调返回 404。公网 HTTPS 域名形式的 `redirect_uri` 与国际版路径尚未验证；上线公网前建议用正式域名再做一次同样验证。测试账号标识和会话令牌未写入仓库。
