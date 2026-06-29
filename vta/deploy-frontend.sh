#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "=================================================="
echo "   Vancouver Transparency Agent - Deploy System  "
echo "=================================================="

# Ensure script runs from project root
cd "$(dirname "$0")"

# Navigate to vta-web directory
if [ -d "vta-web" ]; then
  cd vta-web
else
  echo "[ERROR] Directory vta-web not found."
  exit 1
fi

# Run pages build
echo "[1/2] Building Next.js Edge bundle..."
npm run pages:build

# Run wrangler pages deploy
echo "[2/2] Uploading static bundle to Cloudflare Pages..."
npx wrangler pages deploy .vercel/output/static --project-name vta-web

echo "=================================================="
echo "   Deployment Successfully Completed!             "
echo "=================================================="
