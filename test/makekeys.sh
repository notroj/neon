#!/bin/sh
# Helper script to create CA and server certificates.

srcdir=${1-.}

OPENSSL=${OPENSSL-openssl}
CONF=${srcdir}/openssl.conf
REQ="${OPENSSL} req -config ${CONF}"
CA="${OPENSSL} ca -config ${CONF} -batch"
# MKCERT makes a self-signed cert
MKCERT="${REQ} -x509 -new -days 900"

REQDN=reqDN
export REQDN

set -ex

mkdir ca
touch ca/index.txt
echo 01 > ca/serial

${OPENSSL} genrsa -rand ${srcdir}/../configure > ca/key.pem
${OPENSSL} genrsa -rand ${srcdir}/../configure > client.key

${MKCERT} -key ca/key.pem -out ca/cert.pem <<EOF
US
California
Oakland
Neosign
Random Dept
nowhere.example.com
neon@webdav.org
EOF

# Function to generate appropriate output for `openssl req'.
csr_fields() {
CN=${2-"localhost"}
OU=${1-"Neon QA Dept"}
Org=${3-"Neon Hackers Ltd"}
Locality=${4-"Cambridge"}
State=${5-"Cambridgeshire"}
cat <<EOF
GB
${State}
${Locality}
${Org}
${OU}
${CN}
neon@webdav.org
.
.
EOF
}

csr_fields | ${REQ} -new -key ${srcdir}/server.key -out server.csr

csr_fields "Upper Case Dept" lOcALhost | \
${REQ} -new -key ${srcdir}/server.key -out caseless.csr

csr_fields "Use AltName Dept" nowhere.example.com | \
${REQ} -new -key ${srcdir}/server.key -out altname.csr

csr_fields "Two AltName Dept" nowhere.example.com | \
${REQ} -new -key ${srcdir}/server.key -out altname2.csr

csr_fields "Third AltName Dept" nowhere.example.com | \
${REQ} -new -key ${srcdir}/server.key -out altname3.csr

csr_fields "Fourth AltName Dept" localhost | \
${REQ} -new -key ${srcdir}/server.key -out altname4.csr

csr_fields "Self-Signed" | \
${MKCERT} -key ${srcdir}/server.key -out ssigned.pem

csr_fields "Bad Hostname Department" nohost.example.com | \
${MKCERT} -key ${srcdir}/server.key -out wrongcn.pem

### produce a set of CA certs

csr_fields "First Random CA" "first.example.com" "CAs Ltd." Lincoln Lincolnshire | \
${MKCERT} -key ${srcdir}/server.key -out ca1.pem

csr_fields "Second Random CA" "second.example.com" "CAs Ltd." Falmouth Cornwall | \
${MKCERT} -key ${srcdir}/server.key -out ca2.pem

csr_fields "Third Random CA" "third.example.com" "CAs Ltd." Ipswich Suffolk | \
${MKCERT} -key ${srcdir}/server.key -out ca3.pem

csr_fields "Fourth Random CA" "fourth.example.com" "CAs Ltd." Norwich Norfolk | \
${MKCERT} -key ${srcdir}/server.key -out ca4.pem

cat ca[1234].pem > calist.pem

# Only works with a Linuxy hostname command: continue without it,
# as appropriate tests are skipped if these fail.
hostname=`hostname -s 2>/dev/null` || true
domain=`hostname -d 2>/dev/null` || true
fqdn=`hostname -f 2>/dev/null` || true
if [ "x${hostname}.${domain}" = "x${fqdn}" ]; then
  csr_fields "Wildcard Cert Dept" "*.${domain}" | \
  ${REQ} -new -key ${srcdir}/server.key -out wildcard.csr
  ${CA} -days 900 -in wildcard.csr -out wildcard.cert
fi

csr_fields "Neon Client Cert" ignored.example.com | \
${REQ} -new -key client.key -out client.csr

### requests using special DN.

REQDN=reqDN.doubleCN
csr_fields "Double CN Dept" "nohost.example.com
localhost" | ${REQ} -new -key ${srcdir}/server.key -out twocn.csr

REQDN=reqDN.CNfirst
echo localhost | ${REQ} -new -key ${srcdir}/server.key -out cnfirst.csr

REQDN=reqDN.missingCN
echo GB | ${REQ} -new -key ${srcdir}/server.key -out missingcn.csr

REQDN=reqDN.justEmail
echo blah@example.com | ${REQ} -new -key ${srcdir}/server.key -out justmail.csr

### don't put ${REQ} invocations after here

for f in server client twocn caseless cnfirst missingcn justmail; do
  ${CA} -days 900 -in ${f}.csr -out ${f}.cert
done

${CA} -extensions altExt -days 900 -in altname.csr -out altname.cert
${CA} -extensions altExt2 -days 900 -in altname2.csr -out altname2.cert
${CA} -extensions altExt3 -days 900 -in altname3.csr -out altname3.cert
${CA} -extensions altExt4 -days 900 -in altname4.csr -out altname4.cert

# generate a PKCS12 cert from the client cert: -passOUT because it's the
# passphrase on the OUTPUT cert, confusing...
echo foobar | ${OPENSSL} pkcs12 -export -passout stdin \
   -name "Just A Neon Client Cert" \
   -in client.cert -inkey client.key -out client.p12

# generate a PKCS12 cert with no password
echo | ${OPENSSL} pkcs12 -export -passout stdin \
   -name "An Unencrypted Neon Client Cert" \
   -in client.cert -inkey client.key -out unclient.p12

# generate a PKCS12 cert with no friendly name
echo | ${OPENSSL} pkcs12 -export -passout stdin \
   -in client.cert -inkey client.key -out noclient.p12

### a file containing a complete chain

cat ca/cert.pem server.cert > chain.pem
