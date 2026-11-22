#!/bin/sh
# Apply the nginx patch after /entrypoint.sh has expanded the config template
# and nginx is running, then reload. Runs in the background on every start.
i=0
while [ "$i" -lt 90 ]; do
  i=$((i+1))
  if grep -q 'iris_immutable_assets' /etc/nginx/nginx.conf 2>/dev/null; then
    exit 0
  fi
  if nginx -t >/dev/null 2>&1; then
    /bin/sh /opt/iris-patch/40-iris-static.sh >/dev/null 2>&1
    if nginx -s reload >/dev/null 2>&1; then
      echo "[iris-nginx] patch applied and reloaded"
      exit 0
    fi
  fi
  sleep 1
done
echo "[iris-nginx] patch did not apply in time" >&2
exit 1
