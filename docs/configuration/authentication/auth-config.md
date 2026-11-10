# Auth Config (multiple OIDC issuers)

The auth config lets the boring-registry accept tokens from several OIDC issuers at once, each guarded by claim rules.
A common setup is one identity provider for people, who sign in with `terraform login` or `tofu login`, and the CI system's own OIDC tokens for pipelines, for example [GitHub Actions](#github-actions) or [GitLab CI](#gitlab-ci).

A request is authorized when any configured provider accepts its token: an [API token](api-token.md), the [OIDC flags](oidc.md), Okta, or an issuer from the auth config.
At most one issuer is advertised in `login.v1` for `terraform login`, the others are only accepted.

## Loading

|Flag|Environment Variable|Description|
|---|---|---|
|`--auth-config`|`BORING_REGISTRY_AUTH_CONFIG`|Path to a YAML auth config file|
|`--auth-config-inline`|`BORING_REGISTRY_AUTH_CONFIG_INLINE`|The YAML auth config as a string|

The two options are mutually exclusive.
API tokens are never read from the auth config, keep using `--auth-static-token` for them.

## Reference

```yaml
version: 1                       # required, must be 1
oidc:
  - name: entra                  # required, unique, shown in logs
    issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    audience: <api-app-client-id> # required, the expected "aud" claim
    login:                       # optional, at most one issuer may have it
      client_id: <public-client-app-id>
      scopes: ["api://<api-app-id>/registry.read", "openid"]
      auth_url: ""               # optional, overrides the authorization URL from discovery
    claims:                      # optional claim rules
      roles: ["Registry.Read"]

  - name: github-actions
    issuer: https://token.actions.githubusercontent.com
    audience: boring-registry
    claims:
      repository_owner: ["my-org"]
```

The grant types and ports in `login.v1` come from the existing `--login-grant-types` and `--login-ports` flags.

The config is decoded strictly: unknown keys, a missing `version`, no issuers, duplicate names, more than one issuer with `login`, and empty claim rules all stop the server at startup.
Leave out the `claims` key to accept any token from an issuer, a `claims` key without rules is an error.
Configuring `login` on an auth config issuer together with `--auth-oidc-issuer` or Okta is also a startup error, because only one of them can be advertised.
When `--auth-oidc-issuer` is used together with the auth config, the name `oidc` is reserved for it.

## Claim rules

`claims` maps a claim name to a list of allowed patterns:

- All listed claims must match, and a claim matches if any of its patterns matches.
- In a pattern, `*` matches any run of characters, including `/`. Everything else is literal and case-sensitive, and a pattern must match the whole value: `my-org` doesn't match `my-org-other`.
- A string claim matches when it matches a pattern. An array claim, such as `groups` or `roles`, matches when any of its string elements matches.
- A missing claim, or a claim that is a number, boolean, object or null, never matches.

!!! warning
    The GitHub Actions issuer and the gitlab.com issuer sign tokens for **every** repository or project on the platform, and a workflow can request any audience.
    Always restrict them with claim rules, such as `repository_owner` on GitHub or `namespace_path` on GitLab.
    The server logs a warning at startup for every issuer without claim rules.

Rejected tokens get a `401` response.
With `--debug`, the server logs which provider rejected the token and which claim failed, without logging the token itself.

## Microsoft Entra ID

People sign in with `terraform login` against Entra ID.

1. Register an **API app** and expose a scope, for example `registry.read`.
   In its manifest, set `"accessTokenAcceptedVersion": 2`.
   Otherwise the access tokens carry the v1 issuer `https://sts.windows.net/<tenant-id>/`, which doesn't match the v2.0 issuer in discovery, and every token is rejected.
2. Register a **public client app** for the CLI, with the redirect URIs `http://localhost:10000/login` up to `http://localhost:10010/login`, matching `--login-ports`, and grant it the API scope.
3. Optionally, define an app role on the API app, assign it to the people who should have access, and add a `roles` claim rule.
   Prefer app roles over `groups`: Entra leaves the `groups` claim out of the token for users in many groups (group overage), and those users would be rejected.

```yaml
  - name: entra
    issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    audience: <api-app-client-id>
    login:
      client_id: <public-client-app-id>
      scopes: ["api://<api-app-id>/registry.read", "openid"]
    claims:
      roles: ["Registry.Read"]
```

The login scope must be the registry's own `api://` scope.
Access tokens for Microsoft Graph scopes can't be verified by third parties.

Terraform and OpenTofu don't refresh tokens, so run `terraform login` again when the access token expires (60-90 minutes by default).

## GitHub Actions

```yaml
  - name: github-actions
    issuer: https://token.actions.githubusercontent.com
    audience: boring-registry
    claims:
      repository_owner: ["my-org"]
```

Stricter rules are possible with any [claim GitHub provides](https://docs.github.com/en/actions/reference/security/oidc), for example:

```yaml
    claims:
      repository: ["my-org/infra-*"]
      ref: ["refs/heads/main", "refs/tags/v*"]
```

In the workflow, request a token for the audience and pass it to Terraform as `TF_TOKEN_<hostname>`.
In the hostname, dots become underscores and dashes become double underscores:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - name: Registry token
    run: |
      TOKEN=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=boring-registry" | jq -r .value)
      echo "::add-mask::$TOKEN"
      echo "TF_TOKEN_registry_example_com=$TOKEN" >> "$GITHUB_ENV"
  - run: terraform init
```

GitHub's tokens expire about five minutes after they're issued, and the lifetime can't be configured.
Terraform only contacts the registry during `terraform init`, so fetch a token right before each `init`.

GitHub Enterprise Cloud with a custom issuer works the same way, with `issuer: https://token.actions.githubusercontent.com/<enterprise-slug>`.

## GitLab CI

```yaml
  - name: gitlab-ci
    issuer: https://gitlab.com        # or the URL of a self-managed instance
    audience: boring-registry
    claims:
      namespace_path: ["my-group", "my-group/*"]
```

```yaml
plan:
  id_tokens:
    REGISTRY_TOKEN:
      aud: boring-registry
  script:
    - export TF_TOKEN_registry_example_com="$REGISTRY_TOKEN"
    - terraform init
    - terraform plan
```

The token lives as long as the job's timeout, or five minutes without one.
`namespace_id` and `project_id` survive group renames, paths are easier to read.
For a self-managed instance, the boring-registry must be able to reach it at startup to fetch its discovery document.

## Helm

Store the config in a ConfigMap, mount it with the chart's existing `volumes` and `volumeMounts` values, and point the server at it:

```yaml
server:
  volumes:
    - name: auth-config
      configMap:
        name: boring-registry-auth-config
  volumeMounts:
    - name: auth-config
      mountPath: /etc/boring-registry
      readOnly: true
  extraEnvs:
    - name: BORING_REGISTRY_AUTH_CONFIG
      value: /etc/boring-registry/auth.yaml
```

Without a volume, for example on platforms where mounting files is awkward, set `BORING_REGISTRY_AUTH_CONFIG_INLINE` to the YAML instead.

## Migrating from a shared API token

1. Add the auth config next to the existing `--auth-static-token`, both keep working.
2. Move pipelines to their CI system's OIDC tokens, and people to `terraform login`.
3. With `--debug`, the server logs `successfully verified token` with the provider name for every request.
   Once no requests are verified by the `static` provider anymore, remove `--auth-static-token`.
