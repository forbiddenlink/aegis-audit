# Check Catalog

Checks implemented by `aegis scan`. Severity is the default; policy can
tighten HSTS/CSP presence but not currently retune quality findings.

Inspired by [Mozilla HTTP Observatory](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring)
and the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/).

## Headers

- **HSTS**: Present, `max-age` >= 180 days, `includeSubDomains`.
- **CSP presence**: header is set.
- **CSP quality** (when present):
  - `'unsafe-inline'` in `script-src` / `default-src` (nonce/hash exception)
  - `'unsafe-eval'` in `script-src` / `default-src`
  - overly broad `script-src` or `object-src` (`*`, `https:`, `http:`, `data:`)
  - missing `base-uri`
- **Referrer-Policy**: Present; `unsafe-url` and `no-referrer-when-downgrade` are weak.
- **Permissions-Policy**: Present.
- **Clickjacking**: `X-Frame-Options` (`DENY` / `SAMEORIGIN`) **or** CSP
  `frame-ancestors`. Either is enough. `ALLOW-FROM` is invalid.
- **X-Content-Type-Options**: `nosniff`.
- **Cross-Origin-Opener-Policy (COOP)**: Present (info; does not deduct score).

## Cookies

- **Secure**: Present if HTTPS.
- **HttpOnly**: Present.
- **SameSite**: Present (`Lax`, `Strict`, or `None`).
- **SameSite=None** requires **Secure**.

## CORS

One anonymous `GET` per scan target with `Origin: https://example.invalid`. No
cookies or other credentials are sent and redirects are not followed.

- **Reflected origin + `Access-Control-Allow-Credentials: true`** (high): any site
  can make credentialed requests and read the response.
- **Reflected origin, no credentials** (medium).
- **`*` + credentials `true`** (low): browsers reject this combination, so it is a
  misconfiguration, not an exploitable hole.
- **`*`, no credentials** (info): valid for public resources.
- **No `Access-Control-Allow-Origin`**: pass (no finding).
- The probe follows redirects (apex to www), re-checking each hop with the SSRF guard, and
  classifies the final response; the finding is attributed to the URL you asked about.
- A probe that cannot complete (including a redirect loop or one to a blocked host) is listed in `failed_targets` as
  `<url> (CORS probe)`, never counted as a pass.

## HTTPS Hygiene

- **Final URL**: Must be `https://`.
- **Mixed Content**: No `http://` resources in HTML (`img`, `script`, `link`, `iframe`).
- **Certificate**: Not expired; warn if expiring soon (TLS check).

## RFC 9116 (security.txt)

Fetched automatically at `/.well-known/security.txt` for each origin.

- **Presence**: 4xx/5xx is reported as missing.
- **Contact**: mandatory field.
- **Expires**: field is present.

## Supply Chain (SRI)

- **Integrity**: Third-party `<script src>` and `<link rel="stylesheet">` must
  have an `integrity` attribute. Same-origin and relative URLs are out of scope.
- **Outdated libraries** (medium): passive version-signature detection for
  jQuery, Bootstrap, and AngularJS against a per-library known-safe floor
  (e.g. jQuery < 3.5.0 for CVE-2020-11022/11023).
- **Exposed source maps** (info): a `sourceMappingURL=` reference in
  production JavaScript.

## Content

- **PII / secrets in HTML** (varies): passive regex scan of the response body
  for emails and common credential patterns (AWS keys, Slack tokens, etc.).

## Exposure probing (`--probe`, opt-in)

- **`.env` exposed**: the file is reachable and returns 200.
- **`.git` exposed**: `.git/HEAD` is reachable and returns 200.

## DNS / email

- **SPF**: Present; `+all` is high.
- **DMARC**: Present; `p=none` is medium (monitor-only, not protection).
- **CAA**: Present (low).

## Info Leakage

- **Server**, **X-Powered-By**, **X-AspNet-Version**: present (info).
