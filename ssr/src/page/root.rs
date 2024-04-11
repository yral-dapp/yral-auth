use ic_agent::export::Principal;
use leptos::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};

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
    /// Signature over [types::LoginIntent]
    signature_json: String,
}

#[component]
pub fn RootPage() -> impl IntoView {
    let params = use_params::<RootParams>();
    let prepare_cookie_res = create_blocking_resource(params, |params| async move {
        let Ok(params) = params else {
            return Err("Invalid Params".to_string());
        };
        if let Err(e) = prepare_cookies(params).await {
            return Err(e.to_string());
        }
        Ok(())
    });

    view! {
        <Suspense>
            {move || {
                prepare_cookie_res()
                    .map(|res| {
                        let url = match res {
                            Ok(_) => "/login".to_string(),
                            Err(e) => format!("/error?err={e}"),
                        };
                        view! { <Redirect path=url/> }
                    })
            }}

        </Suspense>
    }
}
