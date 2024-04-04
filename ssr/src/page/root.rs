use leptos::*;

#[component]
pub fn LoginRoot() -> impl IntoView {
    view! {
        <div class="h-dvh w-dvw bg-black flex flex-col justify-center items-center gap-10">
            <h1 class="text-3xl text-white font-bold">Login to Yral</h1>
            <img class="h-56 w-56 object-contain my-8" src="/img/logo.webp"/>
            <p class="text-white text-xl">Continue with</p>
            <div class="flex w-full justify-center gap-8">
                {
                    #[cfg(feature = "oauth-google")]
                    {
                        use crate::auth_providers::google::GoogleLoginButton;
                        view! {
                            <GoogleLoginButton/>
                        }
                    }
                }
            </div>
        </div>
    }
}