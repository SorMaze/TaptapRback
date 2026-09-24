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
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::Html,
    routing::{get, post},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::taptap::{AccessToken, Profile, Region, TapClient, TapError};

#[derive(Clone)]
struct Config {
    cn_client_id: Option<String>,
    global_client_id: Option<String>,
    session_secret: Vec<u8>,
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
        Ok(Self {
            cn_client_id,
            global_client_id,
            session_secret,
        })
    }

    fn client_id(&self, region: Region) -> Option<&str> {
        match region {
            Region::Cn => self.cn_client_id.as_deref(),
            Region::Global => self.global_client_id.as_deref(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: Config,
    tap: TapClient,
    flows: Arc<Mutex<HashMap<String, Arc<Mutex<DeviceFlow>>>>>,
}

struct DeviceFlow {
    region: Region,
    device_code: String,
    expires_at: Instant,
    interval: Duration,
    next_poll_at: Instant,
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
    use base64::Engine;
    let flow_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
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
}

async fn public_config(State(state): State<AppState>) -> Json<PublicConfig> {
    Json(PublicConfig {
        cn: state.config.cn_client_id.is_some(),
        global: state.config.global_client_id.is_some(),
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
    };
    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!("listening on {}", listener.local_addr()?);
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
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
            },
            tap: TapClient::new()
                .unwrap()
                .with_hosts(&upstream_url, &upstream_url),
            flows: Arc::new(Mutex::new(HashMap::new())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        let client = reqwest::Client::new();

        let page = client.get(&base).send().await.unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        assert!(page.text().await.unwrap().contains("游戏登录"));
        let script = client
            .get(format!("{base}/assets/app.js"))
            .send()
            .await
            .unwrap();
        assert_eq!(script.status(), StatusCode::OK);
        assert!(script.text().await.unwrap().contains("/auth/taptap/device"));

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
}
