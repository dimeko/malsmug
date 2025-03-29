#!/bin/sh

export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --fork --config-file=/usr/share/dbus-1/session.conf --print-address`

/etc/init.d/dbus restart

node /js_dast/lib/app.js $1