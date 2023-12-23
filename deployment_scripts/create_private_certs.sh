#!/bin/bash
set -e

# Reference: https://gist.github.com/mtigas/952344
# Reference: https://www.digicert.com/kb/ssl-support/openssl-quick-reference-guide.htm
# https://superuser.com/questions/226192/avoid-password-prompt-for-keys-and-prompts-for-dn-information/226229#226229

# https://github.dev/google/nogotofail/blob/7037dcb23f1fc370de784c36dbb24ae93cd5a58d/nogotofail/mitm/util/ca.py

# Set variables
CERT_DIR="certs"
CA_KEY="RootCA.key"
CA_CERT="RootCA.pem"
CLIENT_KEY="my_client.key"
CLIENT_CSR="my_client.csr"
CLIENT_CERT="my_client.pem"
DAYS_VALID=356

# Check if CA directory exists
if [ ! -d "$CERT_DIR" ]; then
  echo "The Certs directory '$CERT_DIR' does not exist. Creating it now..."
  mkdir -p "$CERT_DIR"
fi

# Create the private certificate authority (CA) key
openssl genrsa -out "${CERT_DIR}/${CA_KEY}" 4096

# Create CA Root Certificate
openssl req \
  -new \
  -x509 \
  -days "${DAYS_VALID}" \
  -key "${CERT_DIR}/${CA_KEY}" \
  -out "${CERT_DIR}/${CA_CERT}" \
  -subj "//C=MI/ST=MIZTIIK/L=grammam/O=Miztiik/OU=MiztiikCorp/CN=miztPvtCA/emailAddress="


# Create client certificate private key
openssl genrsa -out "${CERT_DIR}/${CLIENT_KEY}" 2048

# Create client certificate signing request (CSR)
openssl req \
  -new \
  -key "${CERT_DIR}/${CLIENT_KEY}" \
  -out "${CERT_DIR}/${CLIENT_CSR}" \
  -subj "//C=MI/ST=MIZTIIK/L=grammam/O=Miztiik/OU=MiztiikCorp/CN=miztClient/emailAddress="

# Sign the newly created client cert using your certificate authority
openssl x509 \
  -req \
  -in "${CERT_DIR}/${CLIENT_CSR}" \
  -CA "${CERT_DIR}/${CA_CERT}" \
  -CAkey "${CERT_DIR}/${CA_KEY}" \
  -set_serial 01 \
  -out "${CERT_DIR}/${CLIENT_CERT}" \
  -days "${DAYS_VALID}" \
  -sha256

echo Client certificate signed and generated: ${CERT_DIR}/${CLIENT_CERT}

# Bundle the client key and certificate
cat "${CERT_DIR}/${CLIENT_KEY}" "${CERT_DIR}/${CLIENT_CERT}" > "${CERT_DIR}/${CLIENT_KEY}.pem"
# cat ${CLIENT_ID}.key ${CLIENT_ID}.pem ca.pem > ${CLIENT_ID}.full.pem


# Verify the client certificate
# openssl verify -CAfile ca_certificate.pem client_certificate.pem
openssl verify -CAfile "${CERT_DIR}/${CA_CERT}" "${CERT_DIR}/${CLIENT_CERT}"

echo "---------"
echo `ls "${CERT_DIR}"`
echo "---------"

