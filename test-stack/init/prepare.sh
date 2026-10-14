#!/bin/sh
# One-shot init for the test stack: the Keycloak realm to import. Writes to
# /out (a volume).
#
# Realm `wp`: a stand-in for "your existing realm". Users alice, bob, carol
# (password = username) with FIXED ids, so wp-setup.sh can link alice and bob
# to their WordPress accounts by subject without asking Keycloak. carol is
# deliberately left unlinked in WordPress.
#
# Clients (test-only: direct access grants, so the e2e runner gets user
# tokens without a browser):
#   openwebui  stands in for Open WebUI: its tokens carry `mcp-wordpress` in
#              `aud` (audience mapper), as docs/keycloak.md tells users to set up.
#   other      some other application in the same realm: no such mapper, so
#              its tokens must be refused by this server and by WordPress.
set -eu
apk add --no-cache --quiet jq >/dev/null

mkdir -p /out/realm
user() {  # username id -> user JSON (password = username)
  jq -n --arg u "$1" --arg id "$2" '{
    id: $id, username: $u, enabled: true, emailVerified: true, email: ($u + "@example.com"),
    firstName: $u, lastName: "Example",
    credentials: [{type: "password", value: $u, temporary: false}]
  }'
}
client() {  # clientId secret with-audience-mapper(true|false)
  jq -n --arg c "$1" --arg s "$2" --argjson aud "$3" '{
    clientId: $c, publicClient: false, secret: $s,
    standardFlowEnabled: true, directAccessGrantsEnabled: true,
    redirectUris: ["http://localhost:3000/*"], webOrigins: ["+"],
    protocolMappers: (if $aud then [{
      name: "audience mcp-wordpress", protocol: "openid-connect", protocolMapper: "oidc-audience-mapper",
      config: {"included.custom.audience": "mcp-wordpress", "access.token.claim": "true",
               "id.token.claim": "false", "introspection.token.claim": "true"}
    }] else [] end)
  }'
}
jq -n \
  --argjson alice "$(user alice 00000000-0000-4000-8000-0000000a11ce)" \
  --argjson bob "$(user bob 00000000-0000-4000-8000-000000000b0b)" \
  --argjson carol "$(user carol 00000000-0000-4000-8000-00000000ca01)" \
  --argjson openwebui "$(client openwebui openwebui-test-secret true)" \
  --argjson other "$(client other other-test-secret false)" '{
  realm: "wp", enabled: true, sslRequired: "external", accessTokenLifespan: 300,
  clients: [$openwebui, $other],
  users: [$alice, $bob, $carol]
}' > /out/realm/realm-wp.json
echo "test-stack init done"
