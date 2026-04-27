#!/bin/bash

echo "Fixing firewall rules..."
sudo iptables -P FORWARD ACCEPT
sudo iptables -F FORWARD
echo "Done."