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
use k256::{elliptic_curve::SecretKey, sha2::{Digest, Sha256}, Secp256k1};
use rand::{rngs::StdRng, SeedableRng};
use leptos::{expect_context, ServerFnError};
use leptos_axum::{extract, extract_with_state, ResponseOptions};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use store::{KVStore, KVStoreImpl};
use types::{
    metadata::{GetUserMetadataReq, GetUserMetadataRes, SetUserMetadataReq, SetUserMetadataRes},
    DelegatedIdentityWire, LoginIntent, SignedRefreshTokenClaim,
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
    pub namespace: String,
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

#[cfg(feature = "oauth")]
fn refresh_claim(principal: Principal, referrer_host: url::Host, namespace: String) -> types::RefreshTokenClaim {
    use types::REFRESH_TOKEN_CLAIM_MAX_AGE;

    types::RefreshTokenClaim {
        principal,
        namespace,
        expiry_epoch: current_epoch() + REFRESH_TOKEN_CLAIM_MAX_AGE,
        referrer_host,
    }
}

#[cfg(feature = "oauth")]
fn sign_refresh_claim(
    claim: types::RefreshTokenClaim,
    key: &Key,
) -> Result<types::SignedRefreshTokenClaim, ServerFnError> {
    let signing_key = key.signing();
    let raw = serde_json::to_vec(&claim)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key)?;
    mac.update(&raw);

    let digest = mac.finalize().into_bytes();
    Ok(types::SignedRefreshTokenClaim {
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

#[derive(Clone, Deserialize, Serialize)]
struct RefreshToken {
    principal: Principal,
    namespace: String,
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

async fn fetch_identity_key_from_kv(
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
    fetch_identity_key_from_kv(kv, principal).await
}

async fn generate_and_save_identity_key(kv: &KVStoreImpl) -> Result<SecretKey<Secp256k1>, ServerFnError> {
    let base_identity_key = k256::SecretKey::random(&mut OsRng);
    save_identity_in_kv(kv, base_identity_key.clone()).await?;
    Ok(base_identity_key)
}

async fn save_identity_in_kv(kv: &KVStoreImpl, identity_key: SecretKey<Secp256k1>) -> Result<(), ServerFnError> {

    let identity = Secp256k1Identity::from_private_key(identity_key.clone());
    let principal = identity.sender().unwrap();
    let jwk = identity_key.to_jwk_string();
    kv.write(principal.to_text(), jwk.to_string()).await?;
    Ok(())
}

fn generate_namespaced_identity_key(namespace: &str, from_secret_key: SecretKey<Secp256k1>) -> SecretKey<Secp256k1>{
    let app_name = namespace.as_bytes();

    let mut combined_bytes:Vec<u8> = Vec::new();
    combined_bytes.extend_from_slice(&from_secret_key.to_bytes());
    combined_bytes.extend_from_slice(app_name);

    let mut hasher = Sha256::new();
    hasher.update(combined_bytes);
    let hashed_val = hasher.finalize();

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hashed_val[..32]);

    k256::SecretKey::random(&mut StdRng::from_seed(seed))
}



pub async fn set_cookie_and_get_namespaced_identity(
    response_opts: &ResponseOptions,
    mut jar: SignedCookieJar,
    identity_key: SecretKey<Secp256k1>,
    namespace: &str
) -> Result<DelegatedIdentityWire, ServerFnError> {
    let refresh_max_age = REFRESH_MAX_AGE;
    let identity = Secp256k1Identity::from_private_key(identity_key.clone());
    let principal = identity.sender().unwrap();
    let refresh_token = RefreshToken {
        principal,
        namespace: namespace.to_owned(),
        expiry_epoch_ms: (current_epoch() + refresh_max_age).as_millis(),
    };
    let refresh_token_enc = serde_json::to_string(&refresh_token)?;

    let refresh_cookie = Cookie::build((REFRESH_TOKEN_COOKIE, refresh_token_enc))
        .http_only(true)
        .secure(true)
        .path("/")
        .same_site(SameSite::None)
        .partitioned(true)
        .max_age(refresh_max_age.try_into().unwrap());

    jar = jar.add(refresh_cookie);
    set_cookies(response_opts, jar);

    let namespaced_identity_key = generate_namespaced_identity_key(&namespace, identity_key);
    let namespaced_identity = Secp256k1Identity::from_private_key(namespaced_identity_key);

    Ok(delegate_identity(&namespaced_identity))
}

pub async fn extract_or_generate_identity_impl(namespace: String) -> Result<DelegatedIdentityWire, ServerFnError> {
    let key: Key = expect_context();
    let jar: SignedCookieJar = extract_with_state(&key).await?;
    let kv: KVStoreImpl = expect_context();

    let base_identity_key = if let Some(identity) = try_extract_identity(&jar, &kv).await? {
       identity
    } else {
        generate_and_save_identity_key(&kv).await?
    };

    let resp: ResponseOptions = expect_context();
    let delegated = set_cookie_and_get_namespaced_identity(&resp, jar, base_identity_key, &namespace).await?;

    Ok(delegated)
}

pub async fn logout_identity_impl(namespace: String) -> Result<DelegatedIdentityWire, ServerFnError> {
    let key: Key = expect_context();
    let kv: KVStoreImpl = expect_context();
    let jar: SignedCookieJar = extract_with_state(&key).await?;
    let base_identity_key = generate_and_save_identity_key(&kv).await?;

    let resp: ResponseOptions = expect_context();
    let delegated = set_cookie_and_get_namespaced_identity(&resp, jar, base_identity_key, &namespace).await?;
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

    let principal = verify_refresh_claim(s_claim.clone(), host, &key)?;
    let sk = fetch_identity_key_from_kv(&kv, principal)
        .await?
        .ok_or_else(|| ServerFnError::new("No identity found"))?;


    let namespace = s_claim.claim.namespace.clone();

    let delegated =
        set_cookie_and_get_namespaced_identity(&resp, jar, sk, &namespace).await?;
    Ok(delegated)
}

pub async fn set_user_metadata_impl(
    req: SetUserMetadataReq,
) -> Result<SetUserMetadataRes, ServerFnError> {
    let signature = req.signature;
    let metadata = req.metadata;
    let user_principal = req.user_principal;
    signature.verify_identity(user_principal, metadata.clone().into())?;

    let user = user_principal.to_text();
    let kv: KVStoreImpl = expect_context();
    kv.write_metdata(user, metadata).await?;

    Ok(())
}

pub async fn get_user_metadata_impl(
    req: GetUserMetadataReq,
) -> Result<GetUserMetadataRes, ServerFnError> {
    let user = req.user_principal.to_text();
    let kv: KVStoreImpl = expect_context();
    let metadata = kv.read_metadata(user).await?;

    Ok(metadata)
}
