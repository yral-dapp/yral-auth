mod consts;
mod error;
mod reqs;
pub use types;

use consts::DEFAULT_AUTH_URL;
pub use error::*;
use ic_agent::{export::Principal, Identity};
use reqs::{EmptyReq, GetUserMetadataReqW, SetUserMetadataReqW, UpgradeRefreshClaimReq};
use reqwest::Url;
use serde::{de::DeserializeOwned, Serialize};
use types::{
    metadata::{
        GetUserMetadataReq, GetUserMetadataRes, SetUserMetadataReq, SetUserMetadataRes,
        UserMetadata,
    },
    DelegatedIdentityWire, LoginIntent, SignedRefreshTokenClaim,
};
use yral_identity::ic_agent::sign_message;

#[derive(Clone, Debug)]
pub struct AuthClient {
    base_url: Url,
    client: reqwest::Client,
}

impl Default for AuthClient {
    fn default() -> Self {
        Self {
            base_url: Url::parse(DEFAULT_AUTH_URL).unwrap(),
            client: Default::default(),
        }
    }
}

impl AuthClient {
    pub fn with_base_url(base_url: Url) -> Self {
        Self {
            base_url,
            client: Default::default(),
        }
    }

    async fn send_req<R: DeserializeOwned>(&self, path: &str, body: impl Serialize) -> Result<R> {
        let req = self
            .client
            .post(self.base_url.join("api/").unwrap().join(path).unwrap())
            .json(&body);
        let req = {
            #[cfg(target_arch = "wasm32")]
            {
                req.fetch_credentials_include()
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                req
            }
        };
        let res = req.send().await?;
        if !res.status().is_success() {
            return Err(Error::Api(res.json().await?));
        }
        let data: R = res.json().await?;
        Ok(data)
    }

    pub async fn extract_or_generate_identity(&self) -> Result<DelegatedIdentityWire> {
        self.send_req("extract_or_generate", EmptyReq {}).await
    }

    pub async fn logout_identity(&self) -> Result<DelegatedIdentityWire> {
        self.send_req("logout", EmptyReq {}).await
    }

    pub async fn upgrade_refresh_token_claim(
        &self,
        signed_claim: SignedRefreshTokenClaim,
    ) -> Result<DelegatedIdentityWire> {
        self.send_req(
            "upgrade_refresh_claim",
            UpgradeRefreshClaimReq {
                s_claim: signed_claim,
            },
        )
        .await
    }

    pub async fn set_user_metadata(
        &self,
        identity: &impl Identity,
        metadata: UserMetadata,
    ) -> Result<SetUserMetadataRes> {
        let signature = sign_message(identity, metadata.clone().into())?;
        // unwrap safety: we know the sender is present as we just signed the message
        let sender = identity.sender().unwrap();

        let req = SetUserMetadataReq {
            user_principal: sender,
            metadata,
            signature,
        };

        self.send_req("set_metadata", SetUserMetadataReqW { req })
            .await
    }

    pub async fn get_user_metadata(&self, user_principal: Principal) -> Result<GetUserMetadataRes> {
        let req = GetUserMetadataReq { user_principal };
        self.send_req("get_metadata", GetUserMetadataReqW { req })
            .await
    }

    pub fn prepare_auth_url(&self, identity: &impl Identity, namespace: &str, host: url::Host) -> Result<Url> {
        let intent = LoginIntent {
            referrer_host: host,
        };
        let signature = sign_message(identity, intent.into())?;
        let principal = identity.sender().unwrap();
        let signature_json = serde_json::to_string(&signature)?;
        let mut root_url = self.base_url.clone();
        root_url
            .query_pairs_mut()
            .append_pair("principal", &principal.to_text())
            .append_pair("signature_json", &signature_json)
            .append_pair("namespace", namespace);

        Ok(root_url)
    }
}
