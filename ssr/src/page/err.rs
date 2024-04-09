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
    let params = use_params::<ServerErrParams>();
    let error = move || {
        params()
            .map(|p| p.err)
            .unwrap_or_else(|_| "Server Error".into())
    };

    view! {
        <div class="w-screen h-screen justify-center align-center bg-black gap-4 text-white text-center">
            <h1 class="text-2xl">"Something isn't right"</h1>
            <h3 class="text-lg">{error()}</h3>
        </div>
    }
}
