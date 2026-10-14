#!/bin/sh
# Installs and configures the test WordPress (service wp-setup, wp-cli image):
#   - WordPress core at http://wordpress (the URL every container uses)
#   - users alice (administrator), bob (author), carol (editor); password = username
#   - pretty permalinks, so /wp-json/... routes work
#   - MCP Bearer Auth (built by service bearer-plugin; configured by the
#     MCP_BEARER_* constants in docker-compose.yml), alice and bob matched
#     to their Keycloak subjects (carol is not: the "unmatched user" case)
#   - "Enable Abilities for MCP" from wordpress.org (EAM=off skips it)
# Idempotent: a second run changes nothing that matters.
set -eu
cd /var/www/html

echo "== waiting for the WordPress files and the database"
i=0
until [ -f wp-includes/version.php ] && wp db check >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 90 ] || { echo "WordPress/database did not come up" >&2; exit 1; }
  sleep 2
done
wp core version

if ! wp core is-installed 2>/dev/null; then
  wp core install --url=http://wordpress --title="mcp-wordpress-oauth test" \
    --admin_user=admin --admin_password=admin --admin_email=admin@example.com --skip-email
fi
wp rewrite structure '/%postname%/' >/dev/null

for spec in alice:administrator bob:author carol:editor; do
  u=${spec%%:*}; role=${spec#*:}
  if ! wp user get "$u" --field=ID >/dev/null 2>&1; then
    wp user create "$u" "$u@example.com" --role="$role" --user_pass="$u" --display_name="$u" >/dev/null
  fi
  wp user set-role "$u" "$role" >/dev/null
done

wp plugin activate mcp-bearer-auth
if [ "${EAM:-on}" = on ]; then
  wp plugin is-installed enable-abilities-for-mcp || wp plugin install enable-abilities-for-mcp
  wp plugin activate enable-abilities-for-mcp
fi

wp eval-file /setup/provision.php
echo "== WordPress setup done"
