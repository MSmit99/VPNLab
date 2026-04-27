#!/bin/bash

echo "Configuring VPN Client..."

# Add server to /etc/hosts if not already there
grep -q "vpnlabserver.com" /etc/hosts || echo "10.0.2.4    vpnlabserver.com" | sudo tee -a /etc/hosts

# Wait for tun0 to be created by tlsclient
echo "Waiting for tun0..."
while ! ip link show tun0 > /dev/null 2>&1; do
    sleep 1
done

echo "tun0 found, configuring..."
sudo ifconfig tun0 192.168.53.5/24 up
sudo route add -net 192.168.60.0/24 tun0

echo "Client config complete."
ifconfig tun0
route -n