#!/bin/bash
set -eux

mkdir -p /shared/infra

cp -r /infra/* /shared/infra

cd /shared/infra

/shared/infra/build.sh up -d

# Wait for the port forwarder to be ready
PORT_FORWARDER_HOST=""
while [ -z "$PORT_FORWARDER_HOST" ]; do
    # Get all IPs from the container
    IPS=$(docker exec signoz-port-forwarder hostname -I)
    
    # Iterate through each IP
    for IP in $IPS; do
        # Check if the IP matches the expected format
        # Try to connect to the service with a timeout of 1 second
        if curl -s --connect-timeout 1 http://${IP}:3301 -o /dev/null -w "%{http_code}" | grep -q "200"; then
            PORT_FORWARDER_HOST=$IP
            echo "Found working port forwarder at $PORT_FORWARDER_HOST"
            break
        fi
    done
    
    if [ -z "$PORT_FORWARDER_HOST" ]; then
        echo "Waiting for port forwarder to be ready..."
        sleep 3
    fi
done

socat TCP-LISTEN:1323,fork,reuseaddr TCP:${PORT_FORWARDER_HOST}:1323 &
socat TCP-LISTEN:3301,fork,reuseaddr TCP:${PORT_FORWARDER_HOST}:3301 &
socat TCP-LISTEN:4317,fork,reuseaddr TCP:${PORT_FORWARDER_HOST}:4317 &
wait
