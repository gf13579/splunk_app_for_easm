#!/bin/bash

if [ ! -f package.sh ]; then
    echo "Please run this script from the directory it is in."
    exit 1
fi

APP_DIR="splunk_app_for_easm"

echo "Creating ${APP_DIR}.tgz"

find . -type d -name __pycache__ -delete

COPYFILE_DISABLE=1 tar czf "${APP_DIR}.tgz" -C ../ \
    --exclude '*/__pycache__/*' \
    --exclude '.git*' \
    --exclude '*.tgz' \
    --exclude '*.sh' \
    "${APP_DIR}"

echo "Done!"