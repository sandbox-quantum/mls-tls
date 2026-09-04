set +e
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT



# 1. CA root (ECDSA prime256v1 = P-256)
openssl ecparam -genkey -name prime256v1 \
    -noout -out "$TMP/ca.key.pem" >/dev/null
openssl req -x509 -new \
    -key "$TMP/ca.key.pem" \
    -subj "/CN=TestCA/O=Local" \
    -days 3650 \
    -sha256 \
    -out "$TMP/ca.cert.pem"

# 2. Server key + CSR (P-256)
openssl ecparam -genkey -name prime256v1 \
    -noout -out "$TMP/server.key.pem" >/dev/null 2>&1 #>/dev/null 2>&1
openssl req -new \
    -key "$TMP/server.key.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -out "$TMP/server.csr.pem" >/dev/null 2>&1

# 3. Sign leaf with CA → DER
openssl x509 -req \
    -in "$TMP/server.csr.pem" \
    -CA "$TMP/ca.cert.pem" \
    -CAkey "$TMP/ca.key.pem" \
    -CAcreateserial \
    -days 365 \
    -sha256 \
    -out "$TMP/leaf.der" >/dev/null 2>&1

# 4. CA cert → DER (separate file)
openssl x509 -in "$TMP/ca.cert.pem" -outform DER -out "$TMP/ca.der" -noout >/dev/null 2>&1

# 5. Leaf cert already in DER, but if you want a fresh copy:
openssl x509 -req \
    -in "$TMP/server.csr.pem" \
    -CA "$TMP/ca.cert.pem" \
    -CAkey "$TMP/ca.key.pem" \
    -CAcreateserial \
    -days 365 \
    -sha256 \
    -outform DER \
    -out "$TMP/leaf.der" >/dev/null 2>&1

# 6. Server private key → DER (EC uses `openssl ec`, not `rsa`)
openssl ec -in "$TMP/server.key.pem" -outform DER -out "$TMP/leaf.key.der" >/dev/null 2>&1

absolute=$(readlink -f $0)
script_dir=$(dirname $absolute)

mv "$TMP/ca.der" "$script_dir/"
mv "$TMP/leaf.der" "$script_dir/"
mv "$TMP/leaf.key.der" "$script_dir/"