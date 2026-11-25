# Deploying the gateway remotely: the reference TLS-terminating proxy

The gateway binds loopback only — `readGatewayConfig` refuses any other
host, and that refusal is tested. Remote access is therefore not a
gateway feature; it is a deployment shape, and that shape is a
TLS-terminating authenticating reverse proxy in front of the
loopback-bound gateway:

```
MCP client ──TLS──▶ authenticating reverse proxy ──plain HTTP──▶ gateway (127.0.0.1)
                        │                                            │
                 sets x-rulehouse-identity                    ledger, policy,
                 from the authenticated principal             provenance, upstream
                                                              credential (HTTPS out)
```

The reference below documents an nginx shape. Any authenticating proxy
(OIDC proxy, `auth_request`, forward-auth) works if it satisfies the
same two contracts the tests pin; nothing here certifies a specific
proxy product.

## Reference configuration (nginx)

```nginx
server {
    listen 443 ssl;
    server_name rulehouse.internal.example;

    ssl_certificate     /etc/pki/rulehouse.internal.example.crt;
    ssl_certificate_key /etc/pki/rulehouse.internal.example.key;

    # Authentication challenge of your choice (auth_request, OIDC proxy,
    # forward-auth ...). After it succeeds, $auth_user holds the verified
    # user identifier.

    location = /mcp {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        proxy_buffering off;        # SSE answers must stream, not buffer
        proxy_read_timeout 3600s;   # long-lived tool-call streams

        # MCP session state travels through, never to the identity header:
        proxy_set_header mcp-session-id        $http_mcp_session_id;
        proxy_set_header mcp-protocol-version  $http_mcp_protocol_version;

        # The identity header is SET from the authenticated principal;
        # in nginx a set header overrides any client-supplied copy, and an
        # empty value removes the header entirely. Unauthenticated walk-ups
        # therefore arrive at the gateway with no assertion at all.
        proxy_set_header x-rulehouse-identity  $auth_user;
    }
}
```

The gateway side enables (and must only then enable)
`trustForwardedIdentity: { "header": "x-rulehouse-identity" }`, as in
the commented block of `examples/gateway/rulehouse-gateway.jsonc`.

## The two proxy contracts

These are load-bearing, tested against the gateway, and independent of
the proxy product:

1. **Set, never append, the identity header from the authenticated
   principal.** The gateway refuses *duplicate* assertion headers fail
   closed (`401`): a proxy that appends instead of overriding turns
   every smuggled request into a refusal rather than an impersonation
   — the failure mode is availability, never integrity. (Tested in
   `test/gateway-server.test.ts`.)
2. **Strip what you do not set.** A header the proxy neither sets nor
   clears reaches the gateway verbatim. Either set the identity header
   unconditionally from the authenticated principal (nginx, as above)
   or clear client-supplied copies (`proxy_set_header
   x-rulehouse-identity "";`). A proxy that fails both lets a client
   assert an identity it does not own; this class of misconfiguration
   is why the feature is opt-in and warned about on every startup.

## What this deployment does and does not protect

**It protects:**

- Confidentiality and integrity of client↔gateway traffic (TLS ends at
  the proxy).
- Attribution-basis honesty: decisions made under a proxy-asserted
  identity are recorded `forwarded-header` in the ledger and auditable
  as such, and decisions made under a bearer key are never overridable
  by any header.

**It does not protect:**

- The proxy and everything on the gateway's host: the proxy sees
  request and response plaintext, and anything that can reach
  `127.0.0.1:8080` on the gateway host can reach the gateway directly.
  Harden the host accordingly; the gateway's own upstream credential
  and ledger remain readable to processes under the same user.
- Anything downstream of the gateway: the upstream still sees the
  gateway's upstream credential, and this deployment does not repair
  Atlassian's native audit trails. The attribution honesty note in the
  README applies unchanged.
- Against a compromised or misconfigured proxy: the assertion header
  is only as trustworthy as the proxy deployment that sets it. If the
  proxy can be made to assert an arbitrary name, the gateway can be
  made to act as that identity — the fail-closed duplicate-header
  refusal narrows accidental exposure but not a compromised proxy.
