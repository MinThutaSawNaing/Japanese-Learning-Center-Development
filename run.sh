cat > run.sh <<'SH'
#!/usr/bin/env bash
set -e

IMAGE="japanesecenter:latest"
CONTAINER="japanesecenter_container"
PORT="7777"

# Telegram bot token (TEMPORARY – rotate later)
TELEGRAM_BOT_TOKEN="8491652994:AAGrGTqz1n4bvJf1iqXw_3N6si8j3Y0itik"

echo "[1/3] Build Docker image"
docker build -t "$IMAGE" .

echo "[2/3] Stop & remove old container if exists"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

echo "[3/3] Run container"
docker run -d \
  --name "$CONTAINER" \
  -p ${PORT}:${PORT} \
  --restart unless-stopped \
  -e TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN" \
  "$IMAGE"

echo "Container started:"
docker ps --filter "name=$CONTAINER"
SH

chmod +x run.sh
