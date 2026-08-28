# Argon2id Password Hash Tool

A privacy-first static password hash generator for applications that use Argon2id.

## Privacy

- Hashing is performed locally in the browser.
- The page has no form submission, analytics, database, password storage, or application backend.
- The Argon2 implementation is loaded from a pinned CDN package. Review or self-host its assets if you need an offline or higher-assurance setup.

## Themes

The color theme defaults to **System**, which follows the visitor's operating-system preference and updates if that preference changes while the page is open. Visitors can explicitly choose Light or Dark instead. This non-sensitive display preference is saved only in the browser's `localStorage` under `theme-preference`.

## Output compatibility

The generated output is a standard PHC-formatted Argon2id hash such as:

```text
$argon2id$v=19$m=19456,t=2,p=1$...$...
```

It is compatible with Rust's `argon2` crate when verified with `Argon2::default()`.

## GitHub Pages

1. In the repository, open **Settings → Pages**.
2. Under **Build and deployment**, select **GitHub Actions** as the source.
3. Push to `main`; the included workflow deploys the static site.

## Using a generated hash

Store the complete string in the application database's password-hash column. Do not store the original password or commit generated hashes to Git.
