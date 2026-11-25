# Deploy envoy-vault-jwt

This guide connects the module to Vault, a projected ServiceAccount token, and
an Envoy route. Every host, role, namespace, and identity below is fictional.

## Prerequisites

- Envoy 1.40.2 or a later release with dynamic modules ABI `v0.2.0`.
- `libvault_jwt.so` for your architecture.
- A HashiCorp Vault server that Envoy can reach over HTTPS.
- A Kubernetes Pod with a projected ServiceAccount token.
- A Vault CA certificate that Envoy trusts.

## Step 1: Install the module

Put the shared library where Envoy looks for dynamic modules:

```sh
install -D -m 0755 libvault_jwt-linux-amd64.so \
  /usr/local/lib/envoy-vault-jwt/libvault_jwt.so
export ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib/envoy-vault-jwt
```

The file name must be `libvault_jwt.so`. The module name in the configuration is
`vault_jwt`.

## Step 2: Configure Vault

Enable the JWT auth method. The example mount is `kubernetes`:

```sh
vault auth enable kubernetes
```

Create a role for the workload. The audience must match the audience of the
projected token:

```sh
vault write auth/kubernetes/role/example-workload \
  bound_audiences="vault.example.com" \
  bound_service_account_names="example-workload" \
  bound_service_account_namespaces="example" \
  user_claim="sub" \
  policies="example-machine" \
  ttl="1h"
```

Create a policy with only the two permissions the module needs:

```hcl
path "auth/kubernetes/login" {
  capabilities = ["create", "update"]
}

path "identity/oidc/token/example-machine" {
  capabilities = ["read"]
}
```

Create the identity token role. Set the client ID or a template so that the
token `aud` claim contains the value in `expectedAudience`:

```sh
vault write identity/oidc/role/example-machine \
  key="example-signing-key" \
  client_id="payments-api" \
  ttl="10m"
```

Read the issuer and use it as `expectedIssuer`:

```sh
vault read -field=issuer identity/oidc/config
```

The token TTL must exceed the sum of the refresh margin and the minimum
remaining life. For example, a TTL of 10 minutes works with a 60 second margin
and a 30 second minimum.

## Step 3: Mount the projected token

The module reads the token from an absolute path. Project it into the Envoy
container and mount it read-only. See
[examples/kubernetes-pod.yaml](../../examples/kubernetes-pod.yaml) for a full
Pod example.

```yaml
  volumes:
  - name: vault-token
    projected:
      sources:
      - serviceAccountToken:
          path: token
          audience: vault.example.com
          expirationSeconds: 3600
```

```yaml
    volumeMounts:
    - name: vault-token
      mountPath: /var/run/secrets/vault
      readOnly: true
```

The audience in the volume must match the Vault role bound audience. kubelet
replaces the token file before it expires. The module reopens the path on the
next authentication, so it sees the new token without a restart.

## Step 4: Configure Envoy

Add three pieces: the Vault cluster, the filter, and the per-route block. A full
example is in [examples/envoy.yaml](../../examples/envoy.yaml).

### Vault cluster

```yaml
  - name: vault
    type: STRICT_DNS
    connect_timeout: 1s
    load_assignment:
      cluster_name: vault
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: { address: vault.example.com, port_value: 8200 }
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: vault.example.com
        common_tls_context:
          validation_context:
            trusted_ca:
              filename: /etc/envoy/certs/vault-ca.pem
            match_typed_subject_alt_names:
            - san_type: DNS
              matcher: { exact: "vault.example.com" }
```

Do not add a route to this cluster.

### Filter

```yaml
          http_filters:
          - name: envoy.filters.http.dynamic_modules/vault_jwt
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter
              filter_name: vault_jwt
              dynamic_module_config:
                name: vault_jwt
                metrics_namespace: vault_jwt
              filter_config:
                "@type": type.googleapis.com/google.protobuf.StringValue
                value: |
                  {
                    "vaultCluster": "vault",
                    "vaultAuthority": "vault.example.com:8200",
                    "authMount": "kubernetes",
                    "authRole": "example-workload",
                    "tokenRole": "example-machine",
                    "kubernetesTokenPath": "/var/run/secrets/vault/token",
                    "expectedIssuer": "https://vault.example.com/v1/identity/oidc",
                    "expectedAudience": "payments-api"
                  }
```

The value of `vaultAuthority` must match the certificate identity and the SNI.

### Per-route block

Enable the filter only on routes that need the machine token:

```yaml
                typed_per_filter_config:
                  envoy.filters.http.dynamic_modules/vault_jwt:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilterPerRoute
                    filter_name: vault_jwt
                    dynamic_module_config: { name: vault_jwt }
                    filter_config:
                      "@type": type.googleapis.com/google.protobuf.StringValue
                      value: |
                        {"enabled": true}
```

The route key must match the filter chain name exactly.

## Step 5: Verify

Send a request to a protected route:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Host: payments.example.com' http://127.0.0.1:10000/
```

The result is `200` when Vault is reachable and the token is valid. Check the
statistics:

```sh
curl -s http://127.0.0.1:9901/stats | grep vault_jwt
```

`fetch_success` increases on a successful acquisition. `cache_hit` increases on
later requests. A second request does not increase the Vault request count.

Use an echo upstream or the end-to-end test to confirm that the upstream
receives exactly one `x-machine-token` header and an unchanged `Authorization`
header.

## Deployment rules

- Do not route to the Vault cluster.
- Do not enable the filter on a route that must not carry a machine token.
- Do not put another machine token mechanism on the same route.
- Keep the projected token file read-only and readable only by Envoy.
- Use the same filter configuration for all routes that must share one token.
- Do not log the credential header in an access log.
