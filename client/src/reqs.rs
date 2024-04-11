use serde::{Deserialize, Serialize};
use types::{
    metadata::{GetUserMetadataReq, SetUserMetadataReq},
    SignedRefreshTokenClaim,
};

#[derive(Serialize, Deserialize)]
pub struct UpgradeRefreshClaimReq {
    pub s_claim: SignedRefreshTokenClaim,
}

#[derive(Serialize, Deserialize)]
pub struct SetUserMetadataReqW {
    pub req: SetUserMetadataReq,
}

#[derive(Serialize, Deserialize)]
pub struct GetUserMetadataReqW {
    pub req: GetUserMetadataReq,
}
