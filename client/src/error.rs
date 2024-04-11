use server_fn::ServerFnError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("{0}")]
    Api(ServerFnError),
    #[error("failed to sign: {0}")]
    Identity(#[from] yral_identity::Error),
    #[error("serde json error {0}")]
    SerdeJson(#[from] serde_json::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
