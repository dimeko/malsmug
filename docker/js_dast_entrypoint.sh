#!/bin/sh

# iptables -F
# iptables -X

# iptables -A OUTPUT -j LOG --log-prefix "OUTGOING (BLOCKED): "
# iptables -A OUTPUT -j REJECT

export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --fork --config-file=/usr/share/dbus-1/session.conf --print-address`

/etc/init.d/dbus restart

node /js_dast/lib/app.js $1