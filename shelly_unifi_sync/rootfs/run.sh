#!/bin/sh
set -e

echo "=== Starting Shelly UniFi Sync ==="

# Read ALL config from /data/options.json
if [ -f "/data/options.json" ]; then
    export UNIFI_HOST=$(jq -r '.unifi_host' /data/options.json)
    export UNIFI_PORT=$(jq -r '.unifi_port' /data/options.json)
    export UNIFI_USER=$(jq -r '.unifi_user' /data/options.json)
    export UNIFI_PASS=$(jq -r '.unifi_pass' /data/options.json)
    export UNIFI_SITE=$(jq -r '.unifi_site' /data/options.json)
    export UNIFI_SSL_VERIFY=$(jq -r '.ssl_verify' /data/options.json)
    export NAME_PREFIX=$(jq -r '.name_prefix' /data/options.json)
    export DEBUG=$(jq -r '.debug' /data/options.json)
    
    echo "Config loaded from /data/options.json"
else
    echo "ERROR: /data/options.json not found!"
    exit 1
fi

export HA_CONFIG_PATH="/config"

echo "Config values:"
echo "  UNIFI_HOST: $UNIFI_HOST"
echo "  UNIFI_PORT: $UNIFI_PORT"
echo "  UNIFI_USER: $UNIFI_USER"
echo "  UNIFI_PASS: ${UNIFI_PASS:0:3}***"  # Rodo tik pirmus 3 simbolius
echo "  UNIFI_SITE: $UNIFI_SITE"
echo "  SSL_VERIFY: $UNIFI_SSL_VERIFY"
echo "  NAME_PREFIX: $NAME_PREFIX"

# Validate critical values
if [ "$UNIFI_HOST" = "null" ] || [ -z "$UNIFI_HOST" ]; then
    echo "ERROR: UNIFI_HOST not configured!"
    exit 1
fi

if [ "$UNIFI_USER" = "null" ] || [ -z "$UNIFI_USER" ]; then
    echo "ERROR: UNIFI_USER not configured!"
    exit 1
fi

if [ "$UNIFI_PASS" = "null" ] || [ -z "$UNIFI_PASS" ]; then
    echo "ERROR: UNIFI_PASS not configured!"
    exit 1
fi

cd /app
echo "Starting Flask app with UniFi connection to $UNIFI_HOST..."
exec python3 -m gunicorn \
    --bind 0.0.0.0:8099 \
    --workers 1 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    app:app