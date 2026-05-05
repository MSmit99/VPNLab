#!/bin/bash

echo "Configuring VPN Server..."

# Configure internal network interface
sudo ifconfig enp0s8 192.168.60.1/24 up

# Wait for tun0 to be created by tlsserver
echo "Waiting for tun0..."
while ! ip link show tun0 > /dev/null 2>&1; do
    sleep 1
done

echo "tun0 found, configuring..."
sudo ifconfig tun0 192.168.53.1/24 up
sudo sysctl net.ipv4.ip_forward=1
sudo ip route del 192.168.60.0/24 dev tun0 2>/dev/null || true

echo "Server config complete."
ifconfig tun0
ifconfig enp0s8
route -n