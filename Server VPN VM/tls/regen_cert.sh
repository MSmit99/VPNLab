#!/bin/bash

echo "Regenerating CA and server certificate..."

cd cert_server

# Generate new CA key and certificate (no password)
openssl genrsa -out cakey.pem 2048
openssl req -new -x509 -days 3650 -key cakey.pem -out cacert.pem -subj "/C=US/ST=NY/L=SYR/O=SYR/OU=SYR/CN=seedlabca.com"

# Generate new server certificate
openssl req -new -key server-key.pem -out server-csr.pem -subj "/C=US/ST=NY/O=SYR/OU=SYR/CN=vpnlabserver.com"
openssl x509 -req -days 3650 -in server-csr.pem -CA cacert.pem -CAkey cakey.pem -CAcreateserial -out server-cert.pem

cd ..

# Copy new CA cert to ca_client folder
cp cert_server/cacert.pem ca_client/cacert.pem

# Update symlink in ca_client
cd ca_client
rm -f *.0
ln -s cacert.pem $(openssl x509 -in cacert.pem -noout -subject_hash).0
cd ..

echo "Certificate regenerated successfully."
echo "Verify:"
openssl x509 -in cert_server/server-cert.pem -noout -subject -dates