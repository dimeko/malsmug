#!/bin/sh

# node /sandbox/lib/app.js
cd /sandbox/consumer

python3 -m pip install -r requirements.txt
python3 -u main.py --samples-dir /sandbox/samples \
                   --sandbox-lib /sandbox/lib/app.js \
                   --config-folder /sandbox/config \
                   --bait-website "https://facebook.com"