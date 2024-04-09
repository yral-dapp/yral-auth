use ic_agent::export::Principal;
use leptos::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};

use crate::try_or_redirect_opt;

#[server]
async fn prepare_cookies(params: RootParams) -> Result<(), ServerFnError> {
    use crate::api::server_impl::{set_cookies, TempIdentity};
    use crate::consts::TEMP_IDENTITY_COOKIE;
    use axum_extra::extract::{
        cookie::{Cookie, SameSite},
        CookieJar,
    };
    use http::{header, HeaderMap};
    use leptos_axum::extract;
    use leptos_axum::ResponseOptions;
    use types::TEMP_IDENTITY_MAX_AGE;
    use yral_identity::Signature;

    let sig: Signature = serde_json::from_str(&params.signature_json)?;

    let headers: HeaderMap = extract().await?;
    let referrer_raw = headers
        .get(header::REFERER)
        .ok_or_else(|| ServerFnError::new("No referrer"))?
        .to_str()?;
    let referrer = url::Url::parse(referrer_raw)?;
    let referrer_host = referrer
        .host()
        .ok_or_else(|| ServerFnError::new("No referrer host"))?
        .to_owned();

    let temp_id = TempIdentity {
        principal: params.principal,
        signature: sig,
        referrer_host,
    };
    let temp_id_raw = serde_json::to_string(&temp_id)?;
    let temp_id_cookie = Cookie::build((TEMP_IDENTITY_COOKIE, temp_id_raw))
        .http_only(true)
        .secure(true)
        .path("/")
        .same_site(SameSite::None)
        .max_age(TEMP_IDENTITY_MAX_AGE.try_into().unwrap());

    let mut jar: CookieJar = extract().await?;
    jar = jar.add(temp_id_cookie);
    let resp: ResponseOptions = expect_context();
    set_cookies(&resp, jar);

    Ok(())
}

#[derive(Params, PartialEq, Clone, Debug, Serialize, Deserialize)]
struct RootParams {
    principal: Principal,
    signature_json: String,
}

#[component]
pub fn LoginRoot() -> impl IntoView {
    let params = use_params::<RootParams>();
    let prepare_cookie_res = create_blocking_resource(params, |params| async move {
        let params = try_or_redirect_opt!(params.map_err(|_| "Invalid Params"));
        try_or_redirect_opt!(prepare_cookies(params).await);
        Some(())
    });

    view! {
        <Suspense>
            {move || {
                prepare_cookie_res()
                    .map(|_| {
                        view! {
                            <div class="h-dvh w-dvw bg-black flex flex-col justify-center items-center gap-10">
                                <h1 class="text-3xl text-white font-bold">Login to Yral</h1>
                                <img class="h-56 w-56 object-contain my-8" src="/img/logo.webp"/>
                                <p class="text-white text-xl">Continue with</p>
                                <div class="flex w-full justify-center gap-8">

                                    {#[cfg(feature = "oauth-google")]
                                    {
                                        use crate::auth_providers::google::GoogleLoginButton;
                                        view! { <GoogleLoginButton/> }
                                    }}

                                </div>
                            </div>
                        }
                    })
            }}

        </Suspense>
    }
}
