#!/bin/bash
# setup_client.sh — Run AFTER "sudo ./vpnclient" is already running
# in a separate terminal.
 
echo "[*] Configuring tun0 -> 192.168.53.5..."
sudo ifconfig tun0 192.168.53.5/24 up
 
echo "[*] Adding route: 192.168.60.0/24 -> tun0 (private network via tunnel)..."
sudo route add -net 192.168.60.0/24 tun0 2>/dev/null || true
 
echo "[*] Adding tunnel subnet route (if not auto-added)..."
sudo route add -net 192.168.53.0/24 tun0 2>/dev/null || true
 
echo ""
echo "=== Client ready ==="
route -n
ifconfig tun0
