use leptos::*;
use leptos_router::*;

use std::fmt::Display;

#[macro_export]
macro_rules! try_or_redirect {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                use $crate::page::err::failure_redirect;
                failure_redirect(e);
                return;
            }
        }
    };
}

#[macro_export]
macro_rules! try_or_redirect_opt {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                use $crate::page::err::failure_redirect;
                failure_redirect(e);
                return None;
            }
        }
    };
}

pub fn failure_redirect<E: Display>(err: E) {
    let nav = use_navigate();
    nav(&format!("/error?err={err}"), Default::default());
}

#[derive(Clone, Params, PartialEq)]
struct ServerErrParams {
    err: String,
}

#[component]
pub fn ServerErrorPage() -> impl IntoView {
    let params = use_query::<ServerErrParams>();
    let error = move || {
        params()
            .map(|p| p.err)
            .unwrap_or_else(|_| "Server Error".into())
    };

    view! {
        <div class="flex flex-col w-screen h-screen justify-center items-center bg-black gap-4 text-center">
            <img class="h-36 w-36" src="/img/logo.webp"/>
            <h1 class="text-2xl text-white">"Something isn't right :("</h1>
            <h3 class="text-lg text-white/60">{error()}</h3>
        </div>
    }
}
