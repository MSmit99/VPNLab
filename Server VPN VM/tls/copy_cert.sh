#!/bin/bash

echo "Copying CA cert to Client VM..."
scp cert_server/cacert.pem seed@10.0.2.15:/home/seed/CS364/Project2/tls/ca_client/cacert.pem
echo "Done."