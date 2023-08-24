#!/bin/bash

APP_DIR="splunk_app_for_easm"

echo "Creating ${APP_DIR}.tgz"

find . -type d -name __pycache__ -delete
COPYFILE_DISABLE=1 tar czf "${APP_DIR}.tgz" \
    --exclude '*/__pycache__/*' \
    --exclude '.git*' \
    --exclude '*.tgz' \
    --exclude '*.sh' \
    .

echo "Done!"