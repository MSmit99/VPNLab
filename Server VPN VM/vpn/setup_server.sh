#!/bin/bash
# setup_server.sh — Run AFTER "sudo ./vpnserver" is already running
# in a separate terminal.
 
echo "[*] Configuring tun0 -> 192.168.53.1..."
sudo ifconfig tun0 192.168.53.1/24 up
 
echo "[*] Enabling IP forwarding..."
sudo sysctl net.ipv4.ip_forward=1
 
echo "[*] Adding tunnel subnet route (if not auto-added)..."
sudo route add -net 192.168.53.0/24 tun0 2>/dev/null || true
 
echo ""
echo "=== Server ready ==="
route -n
ifconfig tun0
