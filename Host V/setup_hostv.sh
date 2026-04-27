#!/bin/bash

echo "Configuring Host V routing..."

# Route VPN tunnel network traffic through VPN server gateway
sudo route add -net 192.168.53.0/24 gw 192.168.60.1

echo "Host V config complete."
route -n