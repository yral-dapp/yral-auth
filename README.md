# yral-auth

Auth repo for Yral

## Running the project locally

This enables google oauth

```bash
cargo leptos serve --bin-features oauth-google --lib-features oauth-google --bin-features ssr --lib-features hydrate
```
## Running this with production features

Requires redis as well

```bash
cargo leptos serve --bin-features release-bin --lib-features release-lib
```
