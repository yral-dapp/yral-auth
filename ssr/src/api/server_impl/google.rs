use axum_extra::extract::{
    cookie::{Cookie, Key, SameSite},
    CookieJar, PrivateCookieJar,
};
use ic_agent::export::Principal;
use leptos::{expect_context, ServerFnError};
use leptos_axum::{extract, extract_with_state, ResponseOptions};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreIdTokenVerifier},
    reqwest::async_http_client,
    AuthorizationCode, CsrfToken, Nonce, PkceCodeChallenge, PkceCodeVerifier, Scope,
};
use web_time::Duration;

use crate::consts::TEMP_IDENTITY_COOKIE;

use super::{refresh_claim, set_cookies, sign_refresh_claim, TempIdentity};
use store::{KVStore, KVStoreImpl};
use types::SignedRefreshTokenClaim;

const PKCE_VERIFIER_COOKIE: &str = "google-pkce-verifier";
const CSRF_TOKEN_COOKIE: &str = "google-csrf-token";

pub async fn google_auth_url_impl() -> Result<String, ServerFnError> {
    let oauth2: CoreClient = expect_context();
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token, _) = oauth2
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".into()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let key: Key = expect_context();
    let mut jar: PrivateCookieJar = extract_with_state(&key).await?;

    let cookie_life = Duration::from_secs(60 * 10).try_into().unwrap(); // 10 minutes
    let pkce_cookie = Cookie::build((PKCE_VERIFIER_COOKIE, pkce_verifier.secret().clone()))
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(cookie_life)
        .build();
    jar = jar.add(pkce_cookie);
    let csrf_cookie = Cookie::build((CSRF_TOKEN_COOKIE, csrf_token.secret().clone()))
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(cookie_life)
        .build();
    jar = jar.add(csrf_cookie);

    let resp: ResponseOptions = expect_context();
    set_cookies(&resp, jar);

    Ok(auth_url.to_string())
}

fn no_op_nonce_verifier(_: Option<&Nonce>) -> Result<(), String> {
    Ok(())
}

fn principal_lookup_key(sub_id: &str) -> String {
    format!("google-login-{}", sub_id)
}

async fn try_extract_principal_from_google_sub(
    kv: &KVStoreImpl,
    sub_id: &str,
) -> Result<Option<Principal>, ServerFnError> {
    let Some(principal_text) = kv.read(principal_lookup_key(sub_id)).await? else {
        return Ok(None);
    };
    let principal = Principal::from_text(principal_text)?;

    Ok(Some(principal))
}

async fn associate_principal_with_google_sub(
    kv: &KVStoreImpl,
    principal: Principal,
    sub_id: &str,
) -> Result<Principal, ServerFnError> {
    kv.write(principal_lookup_key(sub_id), principal.to_text())
        .await?;

    Ok(principal)
}

pub async fn perform_google_auth_impl(
    provided_csrf: String,
    auth_code: String,
) -> Result<SignedRefreshTokenClaim, ServerFnError> {
    let key: Key = expect_context();
    let mut jar: PrivateCookieJar = extract_with_state(&key).await?;

    let csrf_cookie = jar
        .get(CSRF_TOKEN_COOKIE)
        .ok_or_else(|| ServerFnError::new("CSRF token cookie not found"))?;
    if provided_csrf != csrf_cookie.value() {
        return Err(ServerFnError::new("CSRF token mismatch"));
    }

    let pkce_cookie = jar
        .get(PKCE_VERIFIER_COOKIE)
        .ok_or_else(|| ServerFnError::new("PKCE verifier cookie not found"))?;
    let pkce_verifier = PkceCodeVerifier::new(pkce_cookie.value().to_owned());

    jar = jar.remove(PKCE_VERIFIER_COOKIE);
    jar = jar.remove(CSRF_TOKEN_COOKIE);
    let resp: ResponseOptions = expect_context();
    set_cookies(&resp, jar);

    let oauth2: CoreClient = expect_context();
    let token_res = oauth2
        .exchange_code(AuthorizationCode::new(auth_code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    // We don't need to use a verifier as exchange takes place over HTTPS and we don't transfer id token over the wire
    // further explained: https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo
    let id_token_verifier = CoreIdTokenVerifier::new_insecure_without_verification();
    let id_token = token_res
        .extra_fields()
        .id_token()
        .ok_or_else(|| ServerFnError::new("Google did not return an ID token"))?;
    // we don't use a nonce
    let claims = id_token.claims(&id_token_verifier, no_op_nonce_verifier)?;
    let sub_id = claims.subject();

    let kv: KVStoreImpl = expect_context();
    let jar: CookieJar = extract().await?;

    let temp_id_cookie = jar
        .get(TEMP_IDENTITY_COOKIE)
        .ok_or_else(|| ServerFnError::new("Attempting google login without a temp identity"))?;
    let temp_id: TempIdentity = serde_json::from_str(temp_id_cookie.value())?;
    let principal = temp_id.principal;
    let namespace = temp_id.namespace.clone();
    let host = temp_id.referrer_host.clone();
    temp_id.validate()?;

    let principal =
        if let Some(identity) = try_extract_principal_from_google_sub(&kv, sub_id).await? {
            identity
        } else {
            associate_principal_with_google_sub(&kv, principal, sub_id).await?
        };
    let claim = refresh_claim(principal, host, namespace);
    let s_claim = sign_refresh_claim(claim, &key)?;

    Ok(s_claim)
}
