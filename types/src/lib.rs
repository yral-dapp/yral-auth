pub mod error;
pub mod metadata;

use error::ApiError;
use ic_agent::identity::{DelegatedIdentity, Secp256k1Identity, SignedDelegation};
use k256::elliptic_curve::JwkEcKey;
use serde::{Deserialize, Serialize};

pub type ApiResult<T> = Result<T, ApiError>;

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
