#!/bin/bash

echo "Adding wrongserver.com to /etc/hosts..."
grep -q "wrongserver.com" /etc/hosts || echo "10.0.2.4    wrongserver.com" | sudo tee -a /etc/hosts
echo "Done."
cat /etc/hosts | grep wrongserver