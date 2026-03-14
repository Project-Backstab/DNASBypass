#!/bin/bash

OPENSSL="./libs/openssl-1.0.2q/bin/openssl"
SSL_DIR="./data/ssl"

DAYS=3650   # 10 years

mkdir -p "$SSL_DIR"

CA_KEY="$SSL_DIR/ca-key.pem"
CA_CERT="$SSL_DIR/ca-cert.pem"

echo "----- Generating DNAS Root CA -----"

$OPENSSL genrsa -out "$CA_KEY" 1024 || exit 1

$OPENSSL req -new -x509 \
    -key "$CA_KEY" \
    -out "$CA_CERT" \
    -days $DAYS \
    -sha256 \
    -subj "/C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority" || exit 1

echo "Root CA created"
echo

declare -A SUBJECTS

SUBJECTS[us]="/C=US/O=Cyberpunks/CN=gate1.us.dnas.playstation.org/emailAddress=the_fog@1337.rip"
SUBJECTS[eu]="/C=EU/O=cyberpunks/CN=gate1.eu.dnas.playstation.org/emailAddress=the_fog@1337.rip"
SUBJECTS[jp]="/C=JP/O=Cyberpunks/CN=gate1.jp.dnas.playstation.org/emailAddress=the_fog@1337.rip"

for REGION in us eu jp
do
    echo "Generating certificate for $REGION..."

    KEY="$SSL_DIR/cert-$REGION-key.pem"
    CSR="$SSL_DIR/cert-$REGION.csr"
    CRT="$SSL_DIR/cert-$REGION.pem"

    # Generate RSA 1024 key
    $OPENSSL genrsa -out "$KEY" 1024 || exit 1

    # CSR
    $OPENSSL req -new \
        -key "$KEY" \
        -out "$CSR" \
        -subj "${SUBJECTS[$REGION]}" || exit 1

    # Sign with CA
    $OPENSSL x509 -req \
        -in "$CSR" \
        -CA "$CA_CERT" \
        -CAkey "$CA_KEY" \
        -CAcreateserial \
        -out "$CRT" \
        -days $DAYS \
        -sha256 || exit 1

    rm "$CSR"

    echo "$REGION certificate generated:"
    $OPENSSL x509 -in "$CRT" -noout -dates
    echo
done

echo "DNAS certificates complete."