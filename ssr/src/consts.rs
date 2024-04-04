use web_time::Duration;

/// Delegation Expiry, 7 days
pub const DELEGATION_MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 7);
/// Refresh expiry, 30 days
pub const REFRESH_MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 30);
pub const REFRESH_TOKEN_COOKIE: &str = "user-identity";

#[cfg(all(feature = "ssr", feature = "oauth-google"))]
pub mod google {
    pub const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
    pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
    pub const GOOGLE_ISSUER_URL: &str = "https://accounts.google.com";
}