pub mod metadata;

use candid::Principal;
use ic_agent::identity::{DelegatedIdentity, Secp256k1Identity, SignedDelegation};
use k256::elliptic_curve::JwkEcKey;
use serde::{Deserialize, Serialize};
use url::Host;
use web_time::Duration;
use yral_identity::msg_builder::Message;

/// Temp identity expiry, 5 minutes
pub const TEMP_IDENTITY_MAX_AGE: Duration = Duration::from_secs(60 * 5);
/// Refresh token claim max age, 10 minutes
pub const REFRESH_TOKEN_CLAIM_MAX_AGE: Duration = Duration::from_secs(60 * 10);

/// Delegated identity that can be serialized over the wire
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DelegatedIdentityWire {
    /// raw bytes of delegated identity's public key
    pub from_key: Vec<u8>,
    /// JWK(JSON Web Key) encoded Secp256k1 secret key
    /// identity allowed to sign on behalf of `from_key`
    pub to_secret: JwkEcKey,
    /// Proof of delegation
    /// connecting from_key to `to_secret`
    pub delegation_chain: Vec<SignedDelegation>,
}

impl TryFrom<DelegatedIdentityWire> for DelegatedIdentity {
    type Error = k256::elliptic_curve::Error;

    fn try_from(identity: DelegatedIdentityWire) -> Result<Self, Self::Error> {
        let to_secret = k256::SecretKey::from_jwk(&identity.to_secret)?;
        let to_identity = Secp256k1Identity::from_private_key(to_secret);
        Ok(Self::new(
            identity.from_key,
            Box::new(to_identity),
            identity.delegation_chain,
        ))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct LoginIntent {
    pub referrer_host: Host,
}

impl From<LoginIntent> for Message {
    fn from(value: LoginIntent) -> Self {
        Message::default()
            .method_name("auth_login".into())
            .args((value.referrer_host.to_string(),))
            // unwrap is safe here because (String,) serialization can't fail
            .unwrap()
            .ingress_max_age(TEMP_IDENTITY_MAX_AGE)
    }
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct RefreshTokenClaim {
    pub principal: Principal,
    pub expiry_epoch: Duration,
    pub namespace: String,
    pub referrer_host: Host,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct SignedRefreshTokenClaim {
    pub claim: RefreshTokenClaim,
    pub digest: Vec<u8>,
}

pub type GoogleAuthMessage = Result<SignedRefreshTokenClaim, String>;
