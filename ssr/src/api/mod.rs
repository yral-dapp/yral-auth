use leptos::{server_fn::codec::Json, *};
use types::{
    metadata::{GetUserMetadataReq, GetUserMetadataRes, SetUserMetadataReq, SetUserMetadataRes},
    DelegatedIdentityWire, SignedRefreshTokenClaim,
};

use crate::consts::NAMESPACE;

#[cfg(feature = "ssr")]
use crate::extractors::JwtAuth;

#[cfg(feature = "ssr")]
pub mod server_impl;

#[cfg(feature = "ssr")]
use leptos_axum::extract;

#[server(endpoint = "extract_or_generate", input = Json, output = Json)]
pub async fn extract_or_generate_identity() -> Result<DelegatedIdentityWire, ServerFnError> {
    let jwt_auth = extract::<JwtAuth>().await?;
    server_impl::extract_or_generate_identity_impl(jwt_auth.namespace).await
}

#[server(endpoint = "logout", input = Json, output = Json)]
pub async fn logout_identity() -> Result<DelegatedIdentityWire, ServerFnError> {
    server_impl::logout_identity_impl(NAMESPACE.into()).await
}

#[server(endpoint = "upgrade_refresh_claim", input = Json, output = Json)]
pub async fn upgrade_refresh_claim(
    s_claim: SignedRefreshTokenClaim,
) -> Result<DelegatedIdentityWire, ServerFnError> {
    server_impl::upgrade_refresh_claim_impl(s_claim).await
}

#[server(endpoint = "set_metadata", input = Json, output = Json)]
pub async fn set_user_metadata(
    req: SetUserMetadataReq,
) -> Result<SetUserMetadataRes, ServerFnError> {
    server_impl::set_user_metadata_impl(req).await
}

#[server(endpoint = "get_metadata", input = Json, output = Json)]
pub async fn get_user_metadata(
    req: GetUserMetadataReq,
) -> Result<GetUserMetadataRes, ServerFnError> {
    server_impl::get_user_metadata_impl(req).await
}
