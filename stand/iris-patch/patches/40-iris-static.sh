#!/bin/sh
# Startup patch for IRIS nginx: gzip + http2 + immutable caching for SvelteKit
# assets proxied from the frontend container.
# NOTE: never serve /_app/ from a copied client build - a stale copy causes a
# client/SSR mismatch and empty case pages.
CONF=/etc/nginx/nginx.conf
BAK=/tmp/nginx.conf.iris-bak

cp "$CONF" "$BAK" 2>/dev/null || true

# 1) gzip
if ! grep -q 'gzip on;' "$CONF"; then
  sed -i 's|^    gzip off;|    gzip on;\n    gzip_comp_level 5;\n    gzip_min_length 1024;\n    gzip_vary on;\n    gzip_proxied any;\n    gzip_types text/plain text/css application/json application/javascript text/javascript application/xml image/svg+xml;|' "$CONF"
fi

# 2) http2 on the TLS listener
sed -i 's/^\( *listen *443 ssl\);/\1 http2;/' "$CONF"

# 3) immutable caching for SvelteKit assets, proxied from the live frontend build
if ! grep -q 'iris_immutable_assets' "$CONF"; then
  awk '{
    if ($0 ~ /^[[:space:]]*location \/ \{/ && !done) {
      print "        # iris_immutable_assets"
      print "        location ^~ /_app/ {"
      print "            proxy_pass http://frontend:5173;"
      print "            proxy_http_version 1.1;"
      print "            proxy_set_header Host $host;"
      print "            proxy_set_header X-Forwarded-Proto $iris_forwarded_proto;"
      print "            proxy_set_header X-Forwarded-Host $iris_forwarded_host;"
      print "            proxy_hide_header Cache-Control;"
      print "            add_header Cache-Control \"public, max-age=31536000, immutable\";"
      print "            access_log off;"
      print "        }"
      print ""
      done=1
    }
    print
  }' "$CONF" > /tmp/nginx.conf.new && mv /tmp/nginx.conf.new "$CONF"
fi

# 4) validate; rollback on error
if ! nginx -t 2>/tmp/nginx-t.log; then
  echo "iris-static: nginx -t failed, rolling back" >&2
  cat /tmp/nginx-t.log >&2
  cp "$BAK" "$CONF" 2>/dev/null || true
fi
