mod taptap;

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::Html,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::taptap::{AccessToken, Profile, Region, TapClient, TapError};

#[derive(Clone)]
struct Config {
    cn_client_id: Option<String>,
    global_client_id: Option<String>,
    session_secret: Vec<u8>,
    public_base_url: Option<String>,
    /// 服务对外挂载的子路径，规范为 "" 或 "/prefix"（无尾斜杠）。
    /// 只影响服务端自己生成的跳转链接；请求路径的前缀由反向代理剥离。
    public_base_path: String,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let cn_client_id = env::var("TAPTAP_CN_CLIENT_ID")
            .ok()
            .filter(|v| !v.is_empty());
        let global_client_id = env::var("TAPTAP_GLOBAL_CLIENT_ID")
            .ok()
            .filter(|v| !v.is_empty());
        if cn_client_id.is_none() && global_client_id.is_none() {
            return Err("set TAPTAP_CN_CLIENT_ID and/or TAPTAP_GLOBAL_CLIENT_ID".into());
        }
        let session_secret = env::var("SESSION_SECRET")
            .map_err(|_| "set SESSION_SECRET to a random value of at least 32 bytes")?
            .into_bytes();
        if session_secret.len() < 32 {
            return Err("SESSION_SECRET must contain at least 32 bytes".into());
        }
        let public_base_url = env::var("PUBLIC_BASE_URL").ok().filter(|v| !v.is_empty());
        if let Some(base) = &public_base_url
            && !base.starts_with("https://")
            && !base.starts_with("http://")
        {
            return Err("PUBLIC_BASE_URL must start with https:// or http://".into());
        }
        let public_base_path = normalize_base_path(env::var("PUBLIC_BASE_PATH").ok())?;
        Ok(Self {
            cn_client_id,
            global_client_id,
            session_secret,
            public_base_url,
            public_base_path,
        })
    }

    fn client_id(&self, region: Region) -> Option<&str> {
        match region {
            Region::Cn => self.cn_client_id.as_deref(),
            Region::Global => self.global_client_id.as_deref(),
        }
    }
}

/// 把 PUBLIC_BASE_PATH 规范成 "" 或 "/prefix"。空值与 "/" 都表示挂在根路径。
/// 只接受字母、数字与 `/ - _`，避免它被拼进服务端生成的 HTML/JS 时带来注入面。
fn normalize_base_path(raw: Option<String>) -> Result<String, String> {
    let Some(raw) = raw else {
        return Ok(String::new());
    };
    let trimmed = raw.trim().trim_end_matches('/');
    let trimmed = trimmed.trim_start_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'-' || b == b'_')
    {
        return Err(
            "PUBLIC_BASE_PATH may only contain ASCII letters, digits, '/', '-' and '_'".into(),
        );
    }
    Ok(format!("/{trimmed}"))
}

#[derive(Clone)]
struct AppState {
    config: Config,
    tap: TapClient,
    flows: Arc<Mutex<HashMap<String, Arc<Mutex<DeviceFlow>>>>>,
    web_flows: Arc<Mutex<HashMap<String, Arc<Mutex<WebFlow>>>>>,
}

struct DeviceFlow {
    region: Region,
    device_code: String,
    expires_at: Instant,
    interval: Duration,
    next_poll_at: Instant,
    finished: bool,
}

struct WebFlow {
    region: Region,
    code_verifier: String,
    redirect_uri: String,
    expires_at: Instant,
    finished: bool,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

type ApiResult<T> = Result<T, (StatusCode, Json<ApiError>)>;

fn error(status: StatusCode, message: &str) -> (StatusCode, Json<ApiError>) {
    (
        status,
        Json(ApiError {
            error: message.into(),
        }),
    )
}

fn tap_error(e: TapError) -> (StatusCode, Json<ApiError>) {
    match e {
        TapError::Rejected(code) => {
            let status = if code == "access_denied" || code == "invalid_token" {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::BAD_REQUEST
            };
            error(status, &code)
        }
        TapError::Upstream | TapError::Malformed => {
            error(StatusCode::BAD_GATEWAY, "taptap_unavailable")
        }
    }
}

#[derive(Deserialize)]
struct SdkLoginRequest {
    region: Region,
    access_token: AccessToken,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Deserialize)]
struct RegionRequest {
    region: Region,
}

#[derive(Serialize)]
struct LoginResponse {
    token_type: &'static str,
    session_token: String,
    expires_in: u64,
    region: Region,
    user: Profile,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    region: Region,
    iat: u64,
    exp: u64,
}

fn now_secs() -> Result<u64, (StatusCode, Json<ApiError>)> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "clock_error"))
}

fn issue_session(state: &AppState, region: Region, user: Profile) -> ApiResult<LoginResponse> {
    if user.openid.is_empty() || user.unionid.is_empty() {
        return Err(error(StatusCode::BAD_GATEWAY, "invalid_taptap_profile"));
    }
    let now = now_secs()?;
    let claims = Claims {
        iss: "taptap-rback".into(),
        sub: user.openid.clone(),
        region,
        iat: now,
        exp: now + 86400,
    };
    let session_token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&state.config.session_secret),
    )
    .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "session_error"))?;
    Ok(LoginResponse {
        token_type: "Bearer",
        session_token,
        expires_in: 86400,
        region,
        user,
    })
}

async fn sdk_login(
    State(state): State<AppState>,
    Json(body): Json<SdkLoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let client_id = state
        .config
        .client_id(body.region)
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "region_not_configured"))?;
    let detailed = body.scopes.iter().any(|scope| scope == "public_profile");
    let user = state
        .tap
        .profile(body.region, client_id, &body.access_token, detailed)
        .await
        .map_err(tap_error)?;
    Ok(Json(issue_session(&state, body.region, user)?))
}

#[derive(Serialize)]
struct DeviceStartResponse {
    flow_id: String,
    qrcode_url: String,
    qr_image: String,
    expires_in: u64,
    interval: u64,
}

async fn device_start(
    State(state): State<AppState>,
    Json(body): Json<RegionRequest>,
) -> ApiResult<Json<DeviceStartResponse>> {
    let client_id = state
        .config
        .client_id(body.region)
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "region_not_configured"))?;
    let code = state
        .tap
        .device_code(body.region, client_id)
        .await
        .map_err(tap_error)?;
    if code.device_code.is_empty() || code.qrcode_url.is_empty() || code.expires_in == 0 {
        return Err(error(StatusCode::BAD_GATEWAY, "invalid_device_code"));
    }
    let qr_svg = qrcode::QrCode::new(code.qrcode_url.as_bytes())
        .map_err(|_| error(StatusCode::BAD_GATEWAY, "invalid_qrcode_url"))?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(320, 320)
        .build();
    let qr_image = format!(
        "data:image/svg+xml;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(qr_svg)
    );
    let interval = code.interval.max(1);
    let mut random = [0u8; 32];
    getrandom::fill(&mut random)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "random_error"))?;
    let flow_id = URL_SAFE_NO_PAD.encode(random);
    let now = Instant::now();
    let mut flows = state.flows.lock().await;
    flows.retain(|_, flow| {
        flow.try_lock()
            .map(|guard| guard.expires_at > now && !guard.finished)
            .unwrap_or(true)
    });
    if flows.len() >= 10_000 {
        return Err(error(StatusCode::SERVICE_UNAVAILABLE, "too_many_flows"));
    }
    flows.insert(
        flow_id.clone(),
        Arc::new(Mutex::new(DeviceFlow {
            region: body.region,
            device_code: code.device_code,
            expires_at: now + Duration::from_secs(code.expires_in),
            interval: Duration::from_secs(interval),
            next_poll_at: now,
            finished: false,
        })),
    );
    Ok(Json(DeviceStartResponse {
        flow_id,
        qrcode_url: code.qrcode_url,
        qr_image,
        expires_in: code.expires_in,
        interval,
    }))
}

#[derive(Serialize)]
struct PublicConfig {
    cn: bool,
    global: bool,
    web: bool,
}

async fn public_config(State(state): State<AppState>) -> Json<PublicConfig> {
    Json(PublicConfig {
        cn: state.config.cn_client_id.is_some(),
        global: state.config.global_client_id.is_some(),
        web: state.config.public_base_url.is_some(),
    })
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn stylesheet() -> ([(header::HeaderName, &'static str); 1], &'static str) {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../web/style.css"),
    )
}

async fn javascript() -> ([(header::HeaderName, &'static str); 1], &'static str) {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../web/app.js"),
    )
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum PollResponse {
    Pending { retry_after: u64 },
    Complete { login: LoginResponse },
}

async fn device_poll(
    State(state): State<AppState>,
    Path(flow_id): Path<String>,
) -> ApiResult<(StatusCode, Json<PollResponse>)> {
    let flow = state
        .flows
        .lock()
        .await
        .get(&flow_id)
        .cloned()
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "flow_not_found"))?;
    let mut flow = flow.lock().await;
    if flow.finished {
        return Err(error(StatusCode::NOT_FOUND, "flow_not_found"));
    }
    if Instant::now() >= flow.expires_at {
        drop(flow);
        state.flows.lock().await.remove(&flow_id);
        return Err(error(StatusCode::GONE, "flow_expired"));
    }
    if Instant::now() < flow.next_poll_at {
        let retry_after = (flow.next_poll_at - Instant::now()).as_secs().max(1);
        return Ok((
            StatusCode::ACCEPTED,
            Json(PollResponse::Pending { retry_after }),
        ));
    }
    let region = flow.region;
    let client_id = state
        .config
        .client_id(region)
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "region_not_configured"))?;
    flow.next_poll_at = Instant::now() + flow.interval;
    let token = match state
        .tap
        .device_token(region, client_id, &flow.device_code)
        .await
    {
        Ok(token) => token,
        Err(TapError::Rejected(code))
            if code == "authorization_pending" || code == "authorization_waiting" =>
        {
            return Ok((
                StatusCode::ACCEPTED,
                Json(PollResponse::Pending {
                    retry_after: flow.interval.as_secs(),
                }),
            ));
        }
        Err(TapError::Rejected(code)) if code == "slow_down" => {
            flow.interval += Duration::from_secs(5);
            flow.next_poll_at = Instant::now() + flow.interval;
            return Ok((
                StatusCode::ACCEPTED,
                Json(PollResponse::Pending {
                    retry_after: flow.interval.as_secs(),
                }),
            ));
        }
        Err(e) => return Err(tap_error(e)),
    };
    let user = state
        .tap
        .profile(region, client_id, &token, true)
        .await
        .map_err(tap_error)?;
    let login = issue_session(&state, region, user)?;
    flow.finished = true;
    drop(flow);
    state.flows.lock().await.remove(&flow_id);
    Ok((StatusCode::OK, Json(PollResponse::Complete { login })))
}

#[derive(Serialize)]
struct WebStartResponse {
    authorize_url: String,
    expires_in: u64,
}

const WEB_FLOW_TTL: Duration = Duration::from_secs(600);

async fn web_start(
    State(state): State<AppState>,
    Json(body): Json<RegionRequest>,
) -> ApiResult<Json<WebStartResponse>> {
    let base = state
        .config
        .public_base_url
        .as_deref()
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "web_login_not_configured"))?;
    let client_id = state
        .config
        .client_id(body.region)
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "region_not_configured"))?;
    let redirect_uri = format!("{}/auth/taptap/web/callback", base.trim_end_matches('/'));
    let mut random = [0u8; 64];
    getrandom::fill(&mut random)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "random_error"))?;
    let flow_id = URL_SAFE_NO_PAD.encode(&random[..32]);
    let code_verifier = URL_SAFE_NO_PAD.encode(&random[32..]);
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    let mut url = Url::parse(&format!("{}/authorize", body.region.authorize_host()))
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "authorize_url_error"))?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("state", &flow_id)
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("scope", "public_profile");
    let now = Instant::now();
    let mut flows = state.web_flows.lock().await;
    flows.retain(|_, flow| {
        flow.try_lock()
            .map(|guard| guard.expires_at > now && !guard.finished)
            .unwrap_or(true)
    });
    if flows.len() >= 10_000 {
        return Err(error(StatusCode::SERVICE_UNAVAILABLE, "too_many_flows"));
    }
    flows.insert(
        flow_id,
        Arc::new(Mutex::new(WebFlow {
            region: body.region,
            code_verifier,
            redirect_uri,
            expires_at: now + WEB_FLOW_TTL,
            finished: false,
        })),
    );
    Ok(Json(WebStartResponse {
        authorize_url: url.into(),
        expires_in: WEB_FLOW_TTL.as_secs(),
    }))
}

#[derive(Deserialize)]
struct WebCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn json_for_script(value: &serde_json::Value) -> String {
    serde_json::to_string(value)
        .unwrap_or_default()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn callback_page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="color-scheme" content="dark" />
    <title>{title} · TapTap 登录</title>
    <style>
      body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
             background: #07111c; color: #ecf5ff;
             font-family: Inter, "Segoe UI", "Microsoft YaHei", sans-serif; }}
      main {{ text-align: center; padding: 24px; }}
      p {{ color: #9cafbf; font-size: 14px; }}
      a {{ color: #79e4d6; }}
    </style>
  </head>
  <body>
    <main>{body}</main>
  </body>
</html>"#
    ))
}

fn callback_error_page(base_path: &str, detail: &str) -> Html<String> {
    let home = format!("{base_path}/");
    callback_page(
        "登录失败",
        &format!(
            "<h1>登录未完成</h1><p>{}</p><p><a href=\"{home}\">返回登录页重试</a></p>",
            html_escape(detail)
        ),
    )
}

fn callback_success_page(base_path: &str, login: &LoginResponse) -> Html<String> {
    let home = format!("{base_path}/");
    let payload = json_for_script(&serde_json::json!({
        "session_token": login.session_token,
        "region": login.region,
        "user": {
            "openid": login.user.openid,
            "name": login.user.name,
            "avatar": login.user.avatar,
        },
    }));
    callback_page(
        "登录成功",
        &format!(
            r#"<h1>授权成功</h1><p>正在返回游戏…</p>
    <script>
      const login = {payload};
      sessionStorage.setItem("taptap_game_session", login.session_token);
      sessionStorage.setItem(
        "taptap_game_profile",
        JSON.stringify({{
          sub: login.user.openid,
          region: login.region,
          name: login.user.name || "TapTap 玩家",
          avatar: login.user.avatar || null,
        }}),
      );
      location.replace("{home}");
    </script>
    <noscript><p><a href="{home}">返回登录页</a></p></noscript>"#
        ),
    )
}

async fn web_callback(
    State(state): State<AppState>,
    Query(query): Query<WebCallbackQuery>,
) -> (StatusCode, Html<String>) {
    let base_path = state.config.public_base_path.clone();
    if let Some(denied) = query.error {
        return (
            StatusCode::BAD_REQUEST,
            callback_error_page(&base_path, &format!("TapTap 返回错误：{denied}")),
        );
    }
    let (Some(code), Some(flow_id)) = (query.code, query.state) else {
        return (
            StatusCode::BAD_REQUEST,
            callback_error_page(&base_path, "回调参数不完整"),
        );
    };
    let flow = state.web_flows.lock().await.get(&flow_id).cloned();
    let Some(flow) = flow else {
        return (
            StatusCode::NOT_FOUND,
            callback_error_page(&base_path, "登录流程不存在或已过期，请重新发起"),
        );
    };
    let mut flow = flow.lock().await;
    if flow.finished {
        return (
            StatusCode::NOT_FOUND,
            callback_error_page(&base_path, "登录流程已被使用，请重新发起"),
        );
    }
    flow.finished = true;
    if Instant::now() >= flow.expires_at {
        drop(flow);
        state.web_flows.lock().await.remove(&flow_id);
        return (
            StatusCode::GONE,
            callback_error_page(&base_path, "登录流程已过期，请重新发起"),
        );
    }
    let region = flow.region;
    let client_id = match state.config.client_id(region) {
        Some(client_id) => client_id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                callback_error_page(&base_path, "该区域未配置"),
            );
        }
    };
    let result = state
        .tap
        .exchange_code(
            region,
            client_id,
            &code,
            &flow.redirect_uri,
            &flow.code_verifier,
        )
        .await;
    let token = match result {
        Ok(token) => token,
        Err(e) => {
            let (status, _) = tap_error(e);
            return (
                status,
                callback_error_page(&base_path, "授权凭证校验失败，请重试"),
            );
        }
    };
    let user = match state.tap.profile(region, client_id, &token, true).await {
        Ok(user) => user,
        Err(e) => {
            let (status, _) = tap_error(e);
            return (
                status,
                callback_error_page(&base_path, "获取用户信息失败，请重试"),
            );
        }
    };
    let login = match issue_session(&state, region, user) {
        Ok(login) => login,
        Err((status, _)) => {
            return (
                status,
                callback_error_page(&base_path, "建立游戏会话失败，请重试"),
            );
        }
    };
    drop(flow);
    state.web_flows.lock().await.remove(&flow_id);
    (StatusCode::OK, callback_success_page(&base_path, &login))
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Claims>> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "missing_bearer_token"))?;
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&state.config.session_secret),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| error(StatusCode::UNAUTHORIZED, "invalid_session"))?
    .claims;
    if claims.iss != "taptap-rback" || claims.iat > now_secs()? {
        return Err(error(StatusCode::UNAUTHORIZED, "invalid_session"));
    }
    Ok(Json(claims))
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/style.css", get(stylesheet))
        .route("/assets/app.js", get(javascript))
        .route("/health", get(|| async { "ok" }))
        .route("/auth/config", get(public_config))
        .route("/auth/taptap/sdk", post(sdk_login))
        .route("/auth/taptap/device", post(device_start))
        .route("/auth/taptap/device/{flow_id}/poll", post(device_poll))
        .route("/auth/taptap/web", post(web_start))
        .route("/auth/taptap/web/callback", get(web_callback))
        .route("/auth/me", get(me))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env().map_err(std::io::Error::other)?;
    let bind: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".into())
        .parse()?;
    let state = AppState {
        config,
        tap: TapClient::new()?,
        flows: Arc::new(Mutex::new(HashMap::new())),
        web_flows: Arc::new(Mutex::new(HashMap::new())),
    };
    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Form, Query};
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn login_flows_validate_with_taptap_before_issuing_session() {
        async fn device_code() -> Json<Value> {
            Json(json!({"success":true,"data":{
                "device_code":"device-secret","qrcode_url":"https://example.test/scan",
                "expires_in":30,"interval":1
            }}))
        }
        async fn device_token(
            State(attempts): State<Arc<AtomicUsize>>,
        ) -> (StatusCode, Json<Value>) {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"success":false,"data":{"error":"authorization_pending"}})),
                )
            } else {
                (
                    StatusCode::OK,
                    Json(json!({"success":true,"data":{
                        "kid":"kid-1","mac_key":"secret","mac_algorithm":"hmac-sha-1","scope":"public_profile"
                    }})),
                )
            }
        }
        async fn profile(
            headers: HeaderMap,
            Query(query): Query<HashMap<String, String>>,
        ) -> Json<Value> {
            assert_eq!(
                query.get("client_id").map(String::as_str),
                Some("test-client")
            );
            assert!(
                headers
                    .get("Authorization")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("MAC id=\"kid-1\"")
            );
            Json(json!({"success":true,"data":{
                "openid":"user-1","unionid":"vendor-user-1","name":"Tester","avatar":"https://example.test/avatar"
            }}))
        }
        let upstream = Router::new()
            .route("/oauth2/v1/device/code", post(device_code))
            .route("/oauth2/v1/token", post(device_token))
            .route("/account/profile/v1", get(profile))
            .route("/account/basic-info/v1", get(profile))
            .with_state(Arc::new(AtomicUsize::new(0)));
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_url = format!("http://{}", upstream_listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(upstream_listener, upstream).await.unwrap() });

        let state = AppState {
            config: Config {
                cn_client_id: Some("test-client".into()),
                global_client_id: None,
                session_secret: vec![42; 32],
                public_base_url: None,
                public_base_path: String::new(),
            },
            tap: TapClient::new()
                .unwrap()
                .with_hosts(&upstream_url, &upstream_url),
            flows: Arc::new(Mutex::new(HashMap::new())),
            web_flows: Arc::new(Mutex::new(HashMap::new())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        let client = reqwest::Client::new();

        let page = client.get(&base).send().await.unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        let page_body = page.text().await.unwrap();
        assert!(page_body.contains("游戏登录"));
        // 资源与接口路径必须是相对路径，服务才能挂在任意子路径下。
        assert!(page_body.contains(r#"href="assets/style.css""#));
        assert!(page_body.contains(r#"src="assets/app.js""#));
        let script = client
            .get(format!("{base}/assets/app.js"))
            .send()
            .await
            .unwrap();
        assert_eq!(script.status(), StatusCode::OK);
        assert!(script.text().await.unwrap().contains("auth/taptap/device"));

        let login_response = client.post(format!("{base}/auth/taptap/sdk"))
            .json(&json!({"region":"cn","access_token":{"kid":"kid-1","mac_key":"secret","mac_algorithm":"hmac-sha-1"},"scopes":["public_profile"]}))
            .send().await.unwrap();
        assert_eq!(login_response.status(), StatusCode::OK);
        let login: Value = login_response.json().await.unwrap();
        assert_eq!(login["user"]["openid"], "user-1");
        let token = login["session_token"].as_str().unwrap();
        let me = client
            .get(format!("{base}/auth/me"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(me.status(), StatusCode::OK);
        assert_eq!(me.json::<Value>().await.unwrap()["sub"], "user-1");

        let invalid = client
            .post(format!("{base}/auth/taptap/sdk"))
            .json(&json!({"region":"cn","access_token":{
                "kid":"kid-1","mac_key":"secret","mac_algorithm":"unsupported"
            }}))
            .send()
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);

        let device = client
            .post(format!("{base}/auth/taptap/device"))
            .json(&json!({"region":"cn"}))
            .send()
            .await
            .unwrap();
        assert_eq!(device.status(), StatusCode::OK);
        let flow: Value = device.json().await.unwrap();
        assert!(
            flow["qr_image"]
                .as_str()
                .unwrap()
                .starts_with("data:image/svg+xml;base64,")
        );
        let poll = client
            .post(format!(
                "{base}/auth/taptap/device/{}/poll",
                flow["flow_id"].as_str().unwrap()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(poll.status(), StatusCode::ACCEPTED);
        assert_eq!(poll.json::<Value>().await.unwrap()["status"], "pending");
        tokio::time::sleep(Duration::from_secs(1)).await;
        let poll_url = format!(
            "{base}/auth/taptap/device/{}/poll",
            flow["flow_id"].as_str().unwrap()
        );
        let completed = client.post(&poll_url).send().await.unwrap();
        assert_eq!(completed.status(), StatusCode::OK);
        let completed: Value = completed.json().await.unwrap();
        assert_eq!(completed["status"], "complete");
        assert_eq!(completed["login"]["user"]["openid"], "user-1");
        assert_eq!(
            client.post(&poll_url).send().await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn web_login_exchanges_code_and_consumes_state() {
        async fn token(Form(form): Form<HashMap<String, String>>) -> Json<Value> {
            assert_eq!(
                form.get("grant_type").map(String::as_str),
                Some("authorization_code")
            );
            assert_eq!(
                form.get("client_id").map(String::as_str),
                Some("test-client")
            );
            assert_eq!(form.get("code").map(String::as_str), Some("code-1"));
            assert!(
                form.get("redirect_uri")
                    .is_some_and(|v| v.ends_with("/auth/taptap/web/callback"))
            );
            assert!(form.get("code_verifier").is_some_and(|v| v.len() >= 43));
            Json(json!({"success":true,"data":{
                "kid":"kid-1","mac_key":"secret","mac_algorithm":"hmac-sha-1","scope":"public_profile"
            }}))
        }
        async fn profile(headers: HeaderMap) -> Json<Value> {
            assert!(
                headers
                    .get("Authorization")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("MAC id=\"kid-1\"")
            );
            Json(json!({"success":true,"data":{
                "openid":"user-1","unionid":"vendor-user-1","name":"Tester","avatar":"https://example.test/avatar"
            }}))
        }
        let upstream = Router::new()
            .route("/oauth2/v1/token", post(token))
            .route("/account/profile/v1", get(profile));
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_url = format!("http://{}", upstream_listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(upstream_listener, upstream).await.unwrap() });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = AppState {
            config: Config {
                cn_client_id: Some("test-client".into()),
                global_client_id: None,
                session_secret: vec![42; 32],
                public_base_url: Some(base.clone()),
                public_base_path: "/taptap".into(),
            },
            tap: TapClient::new()
                .unwrap()
                .with_hosts(&upstream_url, &upstream_url),
            flows: Arc::new(Mutex::new(HashMap::new())),
            web_flows: Arc::new(Mutex::new(HashMap::new())),
        };
        tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        let client = reqwest::Client::new();

        let config = client
            .get(format!("{base}/auth/config"))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(config["web"], true);

        let start = client
            .post(format!("{base}/auth/taptap/web"))
            .json(&json!({"region":"cn"}))
            .send()
            .await
            .unwrap();
        assert_eq!(start.status(), StatusCode::OK);
        let start: Value = start.json().await.unwrap();
        let authorize = Url::parse(start["authorize_url"].as_str().unwrap()).unwrap();
        assert_eq!(authorize.host_str(), Some("accounts.taptap.cn"));
        assert_eq!(authorize.path(), "/authorize");
        let params: HashMap<_, _> = authorize.query_pairs().collect();
        assert_eq!(
            params.get("client_id").map(|v| v.as_ref()),
            Some("test-client")
        );
        let expected_redirect = format!("{base}/auth/taptap/web/callback");
        assert_eq!(
            params.get("redirect_uri").map(|v| v.as_ref()),
            Some(expected_redirect.as_str())
        );
        assert_eq!(
            params.get("code_challenge_method").map(|v| v.as_ref()),
            Some("S256")
        );
        assert!(params.contains_key("code_challenge"));
        let flow_state = params.get("state").unwrap().to_string();

        let wrong_state = client
            .get(format!(
                "{base}/auth/taptap/web/callback?code=code-1&state=wrong"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(wrong_state.status(), StatusCode::NOT_FOUND);

        let callback = client
            .get(format!(
                "{base}/auth/taptap/web/callback?code=code-1&state={flow_state}"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(callback.status(), StatusCode::OK);
        let page = callback.text().await.unwrap();
        assert!(page.contains("taptap_game_session"));
        assert!(page.contains("eyJ"));
        assert!(page.contains("location.replace"));
        // 回调页的跳转目标必须带上服务对外挂载的子路径。
        assert!(page.contains(r#"location.replace("/taptap/")"#));

        let replay = client
            .get(format!(
                "{base}/auth/taptap/web/callback?code=code-1&state={flow_state}"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::NOT_FOUND);

        let denied = client
            .get(format!(
                "{base}/auth/taptap/web/callback?error=access_denied&state={flow_state}"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
        let denied_body = denied.text().await.unwrap();
        assert!(denied_body.contains("access_denied"));
        assert!(denied_body.contains(r#"href="/taptap/""#));
    }

    #[test]
    fn base_path_is_normalized_and_restricted() {
        assert_eq!(normalize_base_path(None).unwrap(), "");
        assert_eq!(normalize_base_path(Some(String::new())).unwrap(), "");
        assert_eq!(normalize_base_path(Some("/".into())).unwrap(), "");
        assert_eq!(
            normalize_base_path(Some("taptap".into())).unwrap(),
            "/taptap"
        );
        assert_eq!(
            normalize_base_path(Some("/taptap/".into())).unwrap(),
            "/taptap"
        );
        assert_eq!(
            normalize_base_path(Some("//deploy/taptap//".into())).unwrap(),
            "/deploy/taptap"
        );
        // 会被拼进服务端生成的 HTML/JS，因此拒绝引号与尖括号。
        assert!(normalize_base_path(Some("/taptap/\"><script>".into())).is_err());
    }
}
