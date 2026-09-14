# Config & Policy

Config file (`aegis.yml` / `examples/aegis-config.yml`) example:

```yaml
scope:
  allow:
    - "staging.myapp.com"
    - "myapp.com"
  allow_private: false

limits:
  rate_per_sec: 2.0
  timeout_sec: 10
  max_html_bytes: 200000
  max_concurrency: 10

policy:
  required_headers:
    strict-transport-security:
      min_max_age: 15552000
      include_subdomains: true
    content-security-policy:
      required: true
    permissions-policy:
      required: true
    referrer-policy:
      required: true
  banned_headers:
    - server
    - x-powered-by
    - x-aspnet-version
```

Unknown keys are rejected at load time (`extra="forbid"`). `policy` remains a
free-form dict so header rules can grow without a schema bump.

