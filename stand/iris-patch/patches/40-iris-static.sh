#!/bin/sh
# Startup patch for IRIS nginx: gzip + http2.
# NOTE: static assets are served by the frontend container (SvelteKit build);
# do NOT redirect /_app/ to a copied client build - that causes a client/SSR
# mismatch and empty case pages.
CONF=/etc/nginx/nginx.conf
BAK=/tmp/nginx.conf.iris-bak

cp "$CONF" "$BAK" 2>/dev/null || true

# 1) gzip
if ! grep -q 'gzip on;' "$CONF"; then
  sed -i 's|^    gzip off;|    gzip on;\n    gzip_comp_level 5;\n    gzip_min_length 1024;\n    gzip_vary on;\n    gzip_proxied any;\n    gzip_types text/plain text/css application/json application/javascript text/javascript application/xml image/svg+xml;|' "$CONF"
fi

# 2) http2 on the TLS listener
sed -i 's/^\( *listen *443 ssl\);/\1 http2;/' "$CONF"

# 3) validate; rollback on error
if ! nginx -t 2>/tmp/nginx-t.log; then
  echo "iris-static: nginx -t failed, rolling back" >&2
  cat /tmp/nginx-t.log >&2
  cp "$BAK" "$CONF" 2>/dev/null || true
fi
