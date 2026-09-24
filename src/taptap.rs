use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Sha1;
use sha2::Sha256;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Region {
    Cn,
    Global,
}

impl Region {
    pub fn accounts_host(self) -> &'static str {
        match self {
            Self::Cn => "https://accounts.tapapis.cn",
            Self::Global => "https://accounts.tapapis.com",
        }
    }

    pub fn open_host(self) -> &'static str {
        match self {
            Self::Cn => "https://open.tapapis.cn",
            Self::Global => "https://open.tapapis.com",
        }
    }

    pub fn authorize_host(self) -> &'static str {
        match self {
            Self::Cn => "https://accounts.taptap.cn",
            Self::Global => "https://www.taptapauth.com",
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct AccessToken {
    pub kid: String,
    pub mac_key: String,
    #[serde(default)]
    pub mac_algorithm: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Profile {
    pub openid: String,
    pub unionid: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
}

#[derive(Deserialize)]
pub struct DeviceCode {
    pub device_code: String,
    pub qrcode_url: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug)]
pub enum TapError {
    Upstream,
    Rejected(String),
    Malformed,
}

#[derive(Clone)]
pub struct TapClient {
    http: Client,
    // Fixed at startup. Never constructed from request data.
    accounts_cn: String,
    accounts_global: String,
    open_cn: String,
    open_global: String,
}

impl TapClient {
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            accounts_cn: Region::Cn.accounts_host().into(),
            accounts_global: Region::Global.accounts_host().into(),
            open_cn: Region::Cn.open_host().into(),
            open_global: Region::Global.open_host().into(),
        })
    }

    fn accounts(&self, region: Region) -> &str {
        match region {
            Region::Cn => &self.accounts_cn,
            Region::Global => &self.accounts_global,
        }
    }

    fn open(&self, region: Region) -> &str {
        match region {
            Region::Cn => &self.open_cn,
            Region::Global => &self.open_global,
        }
    }

    async fn parse_response<T: for<'de> Deserialize<'de>>(
        response: reqwest::Response,
    ) -> Result<T, TapError> {
        let body: Value = response.json().await.map_err(|_| TapError::Malformed)?;
        let data = body.get("data").ok_or(TapError::Malformed)?;
        if body.get("success").and_then(Value::as_bool) == Some(true) {
            serde_json::from_value(data.clone()).map_err(|_| TapError::Malformed)
        } else {
            Err(TapError::Rejected(
                data.get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown_error")
                    .to_owned(),
            ))
        }
    }

    pub async fn device_code(
        &self,
        region: Region,
        client_id: &str,
    ) -> Result<DeviceCode, TapError> {
        let url = format!("{}/oauth2/v1/device/code", self.accounts(region));
        let response = self
            .http
            .post(url)
            .form(&[
                ("client_id", client_id),
                ("response_type", "device_code"),
                ("scope", "public_profile"),
            ])
            .send()
            .await
            .map_err(|_| TapError::Upstream)?;
        Self::parse_response(response).await
    }

    pub async fn device_token(
        &self,
        region: Region,
        client_id: &str,
        code: &str,
    ) -> Result<AccessToken, TapError> {
        let url = format!("{}/oauth2/v1/token", self.accounts(region));
        let response = self
            .http
            .post(url)
            .form(&[
                ("grant_type", "device_token"),
                ("client_id", client_id),
                ("secret_type", "hmac-sha-1"),
                ("code", code),
            ])
            .send()
            .await
            .map_err(|_| TapError::Upstream)?;
        Self::parse_response(response).await
    }

    pub async fn exchange_code(
        &self,
        region: Region,
        client_id: &str,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<AccessToken, TapError> {
        let url = format!("{}/oauth2/v1/token", self.accounts(region));
        let response = self
            .http
            .post(url)
            .form(&[
                ("client_id", client_id),
                ("grant_type", "authorization_code"),
                ("secret_type", "hmac-sha-1"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .map_err(|_| TapError::Upstream)?;
        Self::parse_response(response).await
    }

    pub async fn profile(
        &self,
        region: Region,
        client_id: &str,
        token: &AccessToken,
        detailed: bool,
    ) -> Result<Profile, TapError> {
        if token.kid.is_empty() || token.mac_key.is_empty() {
            return Err(TapError::Rejected("invalid_token".into()));
        }
        let path = if detailed {
            "/account/profile/v1"
        } else {
            "/account/basic-info/v1"
        };
        let mut url = Url::parse(&format!("{}{}", self.open(region), path))
            .map_err(|_| TapError::Malformed)?;
        url.query_pairs_mut().append_pair("client_id", client_id);
        let uri = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_string(),
        };
        let host = url.host_str().ok_or(TapError::Malformed)?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TapError::Malformed)?
            .as_secs();
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| TapError::Malformed)?;
        let nonce = hex_lower(&nonce);
        let authorization = mac_header(token, ts, &nonce, "GET", &uri, host, "443")?;
        let response = self
            .http
            .get(url)
            .header("Authorization", authorization)
            .send()
            .await
            .map_err(|_| TapError::Upstream)?;
        Self::parse_response(response).await
    }

    #[cfg(test)]
    pub fn with_hosts(mut self, accounts: &str, open: &str) -> Self {
        self.accounts_cn = accounts.into();
        self.open_cn = open.into();
        self
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        output.push(HEX[(b >> 4) as usize] as char);
        output.push(HEX[(b & 15) as usize] as char);
    }
    output
}

pub fn mac_header(
    token: &AccessToken,
    ts: u64,
    nonce: &str,
    method: &str,
    uri: &str,
    host: &str,
    port: &str,
) -> Result<String, TapError> {
    if !token.kid.bytes().all(|b| b.is_ascii_graphic() && b != b'"') {
        return Err(TapError::Rejected("invalid_token".into()));
    }
    let normalized = format!("{ts}\n{nonce}\n{method}\n{uri}\n{host}\n{port}\n\n");
    let signature = match token.mac_algorithm.as_deref().unwrap_or("hmac-sha-1") {
        "hmac-sha-1" => {
            let mut mac = Hmac::<Sha1>::new_from_slice(token.mac_key.as_bytes())
                .map_err(|_| TapError::Malformed)?;
            mac.update(normalized.as_bytes());
            STANDARD.encode(mac.finalize().into_bytes())
        }
        "hmac-sha-256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(token.mac_key.as_bytes())
                .map_err(|_| TapError::Malformed)?;
            mac.update(normalized.as_bytes());
            STANDARD.encode(mac.finalize().into_bytes())
        }
        _ => return Err(TapError::Rejected("invalid_token".into())),
    };
    Ok(format!(
        "MAC id=\"{}\",ts=\"{ts}\",nonce=\"{nonce}\",mac=\"{signature}\"",
        token.kid
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_signature_matches_independent_vector() {
        // HMAC-SHA1 value generated independently from the documented normalized string.
        let token = AccessToken {
            kid: "kid-1".into(),
            mac_key: "secret".into(),
            mac_algorithm: Some("hmac-sha-1".into()),
        };
        let header = mac_header(
            &token,
            1618221750,
            "adssd",
            "GET",
            "/account/profile/v1?client_id=abc",
            "open.tapapis.cn",
            "443",
        )
        .unwrap();
        assert_eq!(
            header,
            "MAC id=\"kid-1\",ts=\"1618221750\",nonce=\"adssd\",mac=\"D+UpOI4b0RucsB5m+rYmOqmbbN0=\""
        );
    }

    #[test]
    fn sha256_signature_matches_sdk_supported_algorithm() {
        let token = AccessToken {
            kid: "kid-1".into(),
            mac_key: "secret".into(),
            mac_algorithm: Some("hmac-sha-256".into()),
        };
        let header = mac_header(
            &token,
            1618221750,
            "adssd",
            "GET",
            "/account/profile/v1?client_id=abc",
            "open.tapapis.cn",
            "443",
        )
        .unwrap();
        assert_eq!(
            header,
            "MAC id=\"kid-1\",ts=\"1618221750\",nonce=\"adssd\",mac=\"XilXQH6V0RdvM2IdCejN9jpmEr9BeUucnoMsiUC/EGk=\""
        );
    }
}
