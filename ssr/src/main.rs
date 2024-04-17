use axum::{
    extract::{Path, Request, State},
    response::{IntoResponse, Response},
    routing::get,
};
use leptos::provide_context;
use leptos_axum::handle_server_fns_with_context;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use yral_auth_ssr::{
    app::App,
    state::server::{AppConfig, AppState},
};

async fn server_fn_handler(
    State(app_state): State<AppState>,
    path: Path<String>,
    request: Request<axum::body::Body>,
) -> impl IntoResponse {
    log::info!("{:?}", path);

    handle_server_fns_with_context(
        move || {
            #[cfg(feature = "oauth-google")]
            provide_context(app_state.google_oauth.clone());
            provide_context(app_state.kv.clone());
            provide_context(app_state.cookie_key.clone());
        },
        request,
    )
    .await
}

async fn leptos_routes_handler(
    State(app_state): State<AppState>,
    req: Request<axum::body::Body>,
) -> Response {
    let handler = leptos_axum::render_route_with_context(
        app_state.leptos_options.clone(),
        app_state.routes.clone(),
        move || {
            #[cfg(feature = "oauth-google")]
            provide_context(app_state.google_oauth.clone());
            provide_context(app_state.kv.clone());
            provide_context(app_state.cookie_key.clone());
        },
        App,
    );
    handler(req).await.into_response()
}

fn init_cors() -> CorsLayer {
    use http::{header, Method};

    let origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://0.0.0.0:3000",
        "http://[::1]:3000",
        "http://0.0.0.0:3002",
        "http://localhost:3002",
        "http://127.0.0.1:3002",
        "http://[::1]:3002",
        "https://yral.com",
        "https://auth.yral.com",
        "https://yral-auth.fly.dev",
        "https://hot-or-not-web-leptos-ssr-staging.fly.dev",
    ]
    .map(|o| o.parse().unwrap());

    CorsLayer::new()
        .allow_credentials(true)
        .allow_origin(origins)
        .allow_headers([
            header::ORIGIN,
            header::ACCEPT,
            header::CONTENT_TYPE,
            header::USER_AGENT,
        ])
        .allow_methods([Method::POST, Method::GET, Method::OPTIONS])
}

#[tokio::main]
async fn main() {
    use axum::Router;
    use leptos::*;
    use leptos_axum::{generate_route_list, LeptosRoutes};
    use yral_auth_ssr::app::*;
    use yral_auth_ssr::fileserv::file_and_error_handler;

    // Setting get_configuration(None) means we'll be using cargo-leptos's env values
    // For deployment these variables are:
    // <https://github.com/leptos-rs/start-axum#executing-a-server-on-a-remote-machine-without-the-toolchain>
    // Alternately a file can be specified such as Some("Cargo.toml")
    // The file would need to be included with the executable when moved to deployment
    let conf = get_configuration(None).await.unwrap();
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(App);
    let app_conf = AppConfig::load();
    let app_state = AppState::new(app_conf, leptos_options, routes.clone()).await;

    let cors_layer = ServiceBuilder::new().layer(init_cors());

    // build our application with a route
    let app = Router::new()
        .route(
            "/api/*fn_name",
            get(server_fn_handler).post(server_fn_handler),
        )
        .leptos_routes_with_handler(routes, get(leptos_routes_handler))
        .fallback(file_and_error_handler)
        .layer(cors_layer)
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    logging::log!("listening on http://{}", &addr);
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
