use std::env;

use axum::{async_trait, extract::FromRequestParts};
use http::{header, request::Parts};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct JwtAuth {
    pub namespace: String,
}

pub fn decode_jwt_token(token: &str) -> Result<JwtAuth, String>{
    let pub_identity = env::var("YRAL_PUBLIC_KEY").expect("Yral public key should be present");
    let decoding_key = DecodingKey::from_ec_pem(pub_identity.as_bytes()).map_err(|e| e.to_string())?;

    let token_data = decode::<JwtAuth>(token, &decoding_key, &Validation::new(jsonwebtoken::Algorithm::ES256));
    match token_data {
        Ok(data) => Ok(data.claims),
        Err(e) => Err(e.to_string())
    }
}



#[async_trait]
impl FromRequestParts<()> for JwtAuth {
    type Rejection = String;

    async fn from_request_parts(parts: &mut Parts, _: &()) -> Result<Self, Self::Rejection>{
        let access_token = parts.headers.get(header::AUTHORIZATION).and_then(|val| val.to_str().ok()).and_then(|str| str.split(" ").nth(1));
        match access_token {
            Some(token) => {
                decode_jwt_token(token)
            },
            None => Err("Unauthorized".into())
        }
    }       
}