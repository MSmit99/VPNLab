#!/bin/bash

echo "Updating CA cert symlink..."
cd /home/seed/CS364/Project2/tls/ca_client
rm -f *.0
ln -s cacert.pem $(openssl x509 -in cacert.pem -noout -subject_hash).0
echo "Symlink updated:"
ls -la
cd ..