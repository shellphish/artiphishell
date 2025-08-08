#! /bin/bash
set -eux

FRONTEND_HOST=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' signoz-frontend)
COMPETITION_API_HOST=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' aixcc-competition-server)
OTEL_COLLECTOR_HOST=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' signoz-otel-collector)

# Wait for the competition API to be ready
echo "Waiting for competition API to be ready..."
while ! curl -s -o /dev/null -w "%{http_code}" http://${FRONTEND_HOST}:3301 | grep -q "200"; do
  echo "Competition API not ready yet, waiting..."
  sleep 5
done
echo "Competition API is ready!"

# Send login payload
echo "Sending login payload to competition API..."

curl -X POST "http://${FRONTEND_HOST}:3301/api/v1/register" \
    --compressed \
    -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0' \
    -H 'Accept: application/json, text/plain, */*' \
    -H 'Accept-Language: en-US,en;q=0.5' \
    -H 'Accept-Encoding: gzip, deflate' \
    -H 'Content-Type: application/json' \
    -H 'Authorization: ' \
    -H "Origin: http://${FRONTEND_HOST}:3301" \
    -H 'DNT: 1' \
    -H 'Connection: keep-alive' \
    -H "Referer: http://${FRONTEND_HOST}:3301/signup" \
    -H 'Sec-GPC: 1' \
    -H 'Priority: u=0' \
    -d '{
        "email": "t@t.com",
        "name":"t",
        "orgName":"t",
        "password":"testtest",
        "isAnonymous":false,
        "hasOptedUpdates":false
        }'

echo "Login payload sent!"

socat TCP-LISTEN:1323,fork,reuseaddr TCP:${COMPETITION_API_HOST}:1323 &
socat TCP-LISTEN:3301,fork,reuseaddr TCP:${FRONTEND_HOST}:3301 &
socat TCP-LISTEN:4317,fork,reuseaddr TCP:${OTEL_COLLECTOR_HOST}:4317 &
wait
