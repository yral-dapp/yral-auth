#[cfg(feature = "oauth-google")]
pub mod google;

use axum::response::IntoResponse;
use axum_extra::extract::{
    cookie::{Cookie, Key, SameSite},
    SignedCookieJar,
};
use hmac::{Hmac, Mac};
use http::{header, HeaderMap};
use ic_agent::{
    export::Principal,
    identity::{Delegation, Identity, Secp256k1Identity, SignedDelegation},
};
use k256::sha2::Sha256;
use leptos::{expect_context, ServerFnError};
use leptos_axum::{extract, extract_with_state, ResponseOptions};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use store::{KVStore, KVStoreImpl};
use types::{
    DelegatedIdentityWire, LoginIntent, RefreshTokenClaim, SignedRefreshTokenClaim,
    REFRESH_TOKEN_CLAIM_MAX_AGE,
};
use web_time::{Duration, SystemTime};
use yral_identity::{msg_builder::Message, Signature};

use crate::consts::{DELEGATION_MAX_AGE, REFRESH_MAX_AGE, REFRESH_TOKEN_COOKIE};

fn current_epoch() -> Duration {
    web_time::SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
}

pub fn delegate_identity(from: &impl Identity) -> DelegatedIdentityWire {
    let to_secret = k256::SecretKey::random(&mut OsRng);
    let to_identity = Secp256k1Identity::from_private_key(to_secret.clone());
    let expiry = current_epoch() + DELEGATION_MAX_AGE;
    let expiry_ns = expiry.as_nanos() as u64;
    let delegation = Delegation {
        pubkey: to_identity.public_key().unwrap(),
        expiration: expiry_ns,
        targets: None,
    };
    let sig = from.sign_delegation(&delegation).unwrap();
    let signed_delegation = SignedDelegation {
        delegation,
        signature: sig.signature.unwrap(),
    };

    DelegatedIdentityWire {
        from_key: sig.public_key.unwrap(),
        to_secret: to_secret.to_jwk(),
        delegation_chain: vec![signed_delegation],
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TempIdentity {
    pub principal: Principal,
    pub signature: Signature,
    pub referrer_host: url::Host,
}

impl TempIdentity {
    pub fn validate(self) -> Result<(), yral_identity::Error> {
        let intent = LoginIntent {
            referrer_host: self.referrer_host,
        };
        let msg: Message = intent.into();
        self.signature.verify_identity(self.principal, msg)
    }
}

pub fn set_cookies(resp: &ResponseOptions, jar: impl IntoResponse) {
    let resp_jar = jar.into_response();
    for cookie in resp_jar
        .headers()
        .get_all(header::SET_COOKIE)
        .into_iter()
        .cloned()
    {
        resp.append_header(header::SET_COOKIE, cookie);
    }
}

fn refresh_claim(principal: Principal, referrer_host: url::Host) -> RefreshTokenClaim {
    RefreshTokenClaim {
        principal,
        expiry_epoch: current_epoch() + REFRESH_TOKEN_CLAIM_MAX_AGE,
        referrer_host,
    }
}

fn sign_refresh_claim(
    claim: RefreshTokenClaim,
    key: &Key,
) -> Result<SignedRefreshTokenClaim, ServerFnError> {
    let signing_key = key.signing();
    let raw = serde_json::to_vec(&claim)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key)?;
    mac.update(&raw);

    let digest = mac.finalize().into_bytes();
    Ok(SignedRefreshTokenClaim {
        claim,
        digest: digest.to_vec(),
    })
}

fn verify_refresh_claim(
    s_claim: SignedRefreshTokenClaim,
    referrer_host: url::Host,
    key: &Key,
) -> Result<Principal, ServerFnError> {
    let claim = s_claim.claim;
    if claim.expiry_epoch < current_epoch() {
        return Err(ServerFnError::new("Expired token"));
    }
    if claim.referrer_host != referrer_host {
        return Err(ServerFnError::new("Invalid referrer"));
    }

    let mut mac = Hmac::<Sha256>::new_from_slice(key.signing())?;
    let raw_claim = serde_json::to_vec(&claim)?;
    mac.update(&raw_claim);
    mac.verify_slice(&s_claim.digest)?;

    Ok(claim.principal)
}

#[derive(Clone, Copy, Deserialize, Serialize)]
struct RefreshToken {
    principal: Principal,
    expiry_epoch_ms: u128,
}

async fn extract_principal_from_cookie(
    jar: &SignedCookieJar,
) -> Result<Option<Principal>, ServerFnError> {
    let Some(cookie) = jar.get(REFRESH_TOKEN_COOKIE) else {
        return Ok(None);
    };
    let token: RefreshToken = serde_json::from_str(cookie.value())?;
    if current_epoch().as_millis() > token.expiry_epoch_ms {
        return Ok(None);
    }
    Ok(Some(token.principal))
}

async fn fetch_identity_from_kv(
    kv: &KVStoreImpl,
    principal: Principal,
) -> Result<Option<k256::SecretKey>, ServerFnError> {
    let Some(identity_jwk) = kv.read(principal.to_text()).await? else {
        return Ok(None);
    };

    Ok(Some(k256::SecretKey::from_jwk_str(&identity_jwk)?))
}

pub async fn try_extract_identity(
    jar: &SignedCookieJar,
    kv: &KVStoreImpl,
) -> Result<Option<k256::SecretKey>, ServerFnError> {
    let Some(principal) = extract_principal_from_cookie(jar).await? else {
        return Ok(None);
    };
    fetch_identity_from_kv(kv, principal).await
}

async fn generate_and_save_identity(kv: &KVStoreImpl) -> Result<Secp256k1Identity, ServerFnError> {
    let base_identity_key = k256::SecretKey::random(&mut OsRng);
    let base_identity = Secp256k1Identity::from_private_key(base_identity_key.clone());
    let principal = base_identity.sender().unwrap();

    let base_jwk = base_identity_key.to_jwk_string();
    kv.write(principal.to_text(), base_jwk.to_string()).await?;
    Ok(base_identity)
}

pub async fn update_user_identity(
    response_opts: &ResponseOptions,
    mut jar: SignedCookieJar,
    identity: impl Identity,
) -> Result<DelegatedIdentityWire, ServerFnError> {
    let refresh_max_age = REFRESH_MAX_AGE;
    let refresh_token = RefreshToken {
        principal: identity.sender().unwrap(),
        expiry_epoch_ms: (current_epoch() + refresh_max_age).as_millis(),
    };
    let refresh_token_enc = serde_json::to_string(&refresh_token)?;

    let refresh_cookie = Cookie::build((REFRESH_TOKEN_COOKIE, refresh_token_enc))
        .http_only(true)
        .secure(true)
        .path("/")
        .same_site(SameSite::None)
        .max_age(refresh_max_age.try_into().unwrap());

    jar = jar.add(refresh_cookie);
    set_cookies(response_opts, jar);

    Ok(delegate_identity(&identity))
}

pub async fn extract_or_generate_identity_impl() -> Result<DelegatedIdentityWire, ServerFnError> {
    let key: Key = expect_context();
    let jar: SignedCookieJar = extract_with_state(&key).await?;
    let kv: KVStoreImpl = expect_context();

    let base_identity = if let Some(identity) = try_extract_identity(&jar, &kv).await? {
        Secp256k1Identity::from_private_key(identity)
    } else {
        generate_and_save_identity(&kv).await?
    };

    let resp: ResponseOptions = expect_context();
    let delegated = update_user_identity(&resp, jar, base_identity).await?;

    Ok(delegated)
}

pub async fn logout_identity_impl() -> Result<DelegatedIdentityWire, ServerFnError> {
    let key: Key = expect_context();
    let kv: KVStoreImpl = expect_context();
    let jar: SignedCookieJar = extract_with_state(&key).await?;
    let base_identity = generate_and_save_identity(&kv).await?;

    let resp: ResponseOptions = expect_context();
    let delegated = update_user_identity(&resp, jar, base_identity).await?;
    Ok(delegated)
}

pub async fn upgrade_refresh_claim_impl(
    s_claim: SignedRefreshTokenClaim,
) -> Result<DelegatedIdentityWire, ServerFnError> {
    let key: Key = expect_context();
    let kv: KVStoreImpl = expect_context();
    let jar: SignedCookieJar = extract_with_state(&key).await?;
    let resp: ResponseOptions = expect_context();

    let headers: HeaderMap = extract().await?;
    let referrer_raw = headers
        .get(header::REFERER)
        .ok_or_else(|| ServerFnError::new("No referrer"))?
        .to_str()?;
    let referrer = url::Url::parse(referrer_raw)?;
    let host = referrer
        .host()
        .ok_or_else(|| ServerFnError::new("No referrer host"))?
        .to_owned();

    let principal = verify_refresh_claim(s_claim, host, &key)?;
    let sk = fetch_identity_from_kv(&kv, principal)
        .await?
        .ok_or_else(|| ServerFnError::new("No identity found"))?;

    let delegated =
        update_user_identity(&resp, jar, Secp256k1Identity::from_private_key(sk)).await?;
    Ok(delegated)
}
