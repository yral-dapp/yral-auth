use leptos::{server_fn::codec::Json, *};
use types::DelegatedIdentityWire;

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
