use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use leptos::LeptosOptions;
use leptos_router::RouteListing;
use serde::Deserialize;
use serde_with::serde_as;
use store::KVStoreImpl;

#[derive(FromRef, Clone)]
pub struct AppState {
    pub leptos_options: LeptosOptions,
    pub routes: Vec<RouteListing>,
    pub cookie_key: Key,
    #[cfg(feature = "oauth-google")]
    pub google_oauth: openidconnect::core::CoreClient,
    pub kv: KVStoreImpl,
}

impl AppState {
    #[cfg(feature = "oauth-google")]
    fn google_init(conf: &AppConfig) -> openidconnect::core::CoreClient {
        use crate::consts::google::{GOOGLE_AUTH_URL, GOOGLE_ISSUER_URL, GOOGLE_TOKEN_URL};
        use openidconnect::{
            core::CoreClient, AuthUrl, ClientId, ClientSecret, IssuerUrl, RedirectUrl, TokenUrl,
        };

        let client_id = conf.google_client_id.clone();
        let client_secret = conf.google_client_secret.clone();
        let redirect_uri = conf.google_redirect_url.clone();

        CoreClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            IssuerUrl::new(GOOGLE_ISSUER_URL.to_string()).unwrap(),
            AuthUrl::new(GOOGLE_AUTH_URL.to_string()).unwrap(),
            Some(TokenUrl::new(GOOGLE_TOKEN_URL.to_string()).unwrap()),
            None,
            // We don't validate id_tokens against Google's public keys
            Default::default(),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap())
    }

    async fn kv_init(conf: &AppConfig) -> KVStoreImpl {
        #[cfg(feature = "redis-kv")]
        {
            use store::redis_kv::RedisKV;
            KVStoreImpl::Redis(RedisKV::new(&conf.redis_url).await.unwrap())
        }
        #[cfg(not(feature = "redis-kv"))]
        {
            use store::redb_kv::ReDBKV;
            _ = conf;
            KVStoreImpl::ReDB(ReDBKV::new().unwrap())
        }
    }

    pub async fn new(
        conf: AppConfig,
        leptos_options: LeptosOptions,
        routes: Vec<RouteListing>,
    ) -> Self {
        Self {
            leptos_options,
            routes,
            cookie_key: Key::from(&conf.cookie_key),
            #[cfg(feature = "oauth-google")]
            google_oauth: Self::google_init(&conf),
            kv: Self::kv_init(&conf).await,
        }
    }
}

#[serde_as]
#[derive(Deserialize, Debug, Clone)]
pub struct AppConfig {
    #[cfg_attr(not(feature = "release-bin"), serde(default = "fallback_cookie_key"))]
    #[serde_as(as = "serde_with::hex::Hex")]
    cookie_key: [u8; 64],
    #[cfg(feature = "oauth-google")]
    google_client_id: String,
    #[cfg(feature = "oauth-google")]
    google_client_secret: String,
    #[cfg(feature = "oauth-google")]
    google_redirect_url: String,
    #[cfg(feature = "redis-kv")]
    redis_url: String,
}

#[cfg(not(feature = "release-bin"))]
fn fallback_cookie_key() -> [u8; 64] {
    log::warn!("using fallback cookie key");
    [
        18, 103, 178, 145, 80, 3, 101, 196, 32, 67, 224, 75, 198, 156, 242, 74, 49, 73, 91, 216,
        147, 111, 200, 214, 121, 66, 131, 103, 94, 40, 143, 173, 117, 89, 113, 146, 45, 69, 207,
        28, 160, 180, 56, 223, 79, 200, 71, 243, 156, 176, 178, 172, 235, 58, 69, 103, 62, 255, 35,
        28, 221, 184, 141, 201,
    ]
}

impl AppConfig {
    pub fn load() -> Self {
        Figment::new()
            .merge(Toml::file("config.toml"))
            .merge(Env::raw())
            .extract()
            .unwrap()
    }
}
