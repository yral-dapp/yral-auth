use leptos::{server_fn::codec::Json, *};
use types::{DelegatedIdentityWire, SignedRefreshTokenClaim};

#[cfg(feature = "ssr")]
pub mod server_impl;

#[server(endpoint = "extract_or_generate", input = Json, output = Json)]
pub async fn extract_or_generate_identity() -> Result<DelegatedIdentityWire, ServerFnError> {
    server_impl::extract_or_generate_identity_impl().await
}

#[server(endpoint = "logout", input = Json, output = Json)]
pub async fn logout_identity() -> Result<DelegatedIdentityWire, ServerFnError> {
    server_impl::logout_identity_impl().await
}

#[server(endpoint = "upgrade_refresh_claim", input = Json, output = Json)]
pub async fn upgrade_refresh_claim(
    s_claim: SignedRefreshTokenClaim,
) -> Result<DelegatedIdentityWire, ServerFnError> {
    server_impl::upgrade_refresh_claim_impl(s_claim).await
}
