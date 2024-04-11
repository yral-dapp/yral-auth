use candid::Principal;
use serde::{Deserialize, Serialize};
use yral_identity::{msg_builder::Message, Signature};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserMetadata {
    pub user_canister_id: Principal,
    pub user_name: String,
}

impl From<UserMetadata> for Message {
    fn from(value: UserMetadata) -> Self {
        Message::default()
            .method_name("set_user_metadata".into())
            .args((value.user_canister_id, value.user_name))
            // unwrap is safe here because (Principal, String) serialization can't fail
            .unwrap()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SetUserMetadataReq {
    pub user_principal: Principal,
    pub metadata: UserMetadata,
    pub signature: Signature,
}

pub type SetUserMetadataRes = ();

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct GetUserMetadataReq {
    pub user_principal: Principal,
}

pub type GetUserMetadataRes = Option<UserMetadata>;
