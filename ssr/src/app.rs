use crate::{
    error_template::{AppError, ErrorTemplate},
    page::{err::ServerErrorPage, root::LoginRoot},
};
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

#[component]
fn NotFound() -> impl IntoView {
    let mut outside_errors = Errors::default();
    outside_errors.insert_with_default_key(AppError::NotFound);
    view! { <ErrorTemplate outside_errors/> }
}

#[component(transparent)]
fn GoogleAuthRedirectHandlerRoute() -> impl IntoView {
    let path = "/google_redirect";
    #[cfg(feature = "oauth-google")]
    {
        use crate::page::google_redirect::GoogleRedirectHandler;
        view! { <Route path view=GoogleRedirectHandler/> }
    }
    #[cfg(not(feature = "oauth-google"))]
    {
        view! { <Route path view=NotFound/> }
    }
}

#[component(transparent)]
fn GoogleAuthRedirectorRoute() -> impl IntoView {
    let path = "/perform_google_redirect";
    #[cfg(feature = "oauth-google")]
    {
        use crate::page::google_redirect::GoogleRedirector;
        view! { <Route path view=GoogleRedirector/> }
    }
    #[cfg(not(feature = "oauth-google"))]
    {
        view! { <Route path view=NotFound/> }
    }
}

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/yral-auth-ssr.css"/>

        // sets the document title
        <Title text="Welcome to Leptos"/>

        // content for this welcome page
        <Router fallback=|| view! { <NotFound/> }.into_view()>
            <main>
                <Routes>
                    <Route path="" view=LoginRoot/>
                    <GoogleAuthRedirectHandlerRoute/>
                    <GoogleAuthRedirectorRoute/>
                    <Route path="/error" view=ServerErrorPage/>
                </Routes>
            </main>
        </Router>
    }
}
