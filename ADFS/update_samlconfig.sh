#!/bin/bash
# curl -L https://github.com/vitsidmar/practice/raw/main/Linux/update_samlconfig.sh -o update_samlconfig.sh && chmod +x update_samlconfig.sh && ./update_samlconfig.sh

sudo apt-get update -y
sudo apt-get install -y libxml2-utils jq xmlstarlet

OUTPUT_DIR="/root/adfs"
SP_DOMAIN=$(hostname)
IDP_DOMAIN="adfs.migrate.local"
METADATA_FILE="$OUTPUT_DIR/federationmetadata.xml"
SETTINGS_FILE="$OUTPUT_DIR/saml/settings.json"
CERT_INFO="/C=CH/ST=Zurich/L=Monchaltorf/O=Sidmar/OU=IT/CN=IT@$SP_DOMAIN"

curl -k -o $OUTPUT_DIR/federationmetadata.xml https://$IDP_DOMAIN/FederationMetadata/2007-06/federationmetadata.xml
git clone https://github.com/SAML-Toolkits/python3-saml.git /tmp/python3-saml
cp -r /tmp/python3-saml/demo-flask/* $OUTPUT_DIR
rm -rf /tmp/python3-saml

namespace="urn:oasis:names:tc:SAML:2.0:metadata"
ds="http://www.w3.org/2000/09/xmldsig#"
entityId=$(xmlstarlet sel -N md=$namespace -t -v "//md:EntityDescriptor/@entityID" "$METADATA_FILE")
ssoUrl=$(xmlstarlet sel -N md=$namespace -t -v "//md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location" "$METADATA_FILE")
sloUrl=$(xmlstarlet sel -N md=$namespace -t -v "//md:IDPSSODescriptor/md:SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location" "$METADATA_FILE")
x509cert=$(xmlstarlet sel -N md=$namespace -N ds=$ds -t -v "//md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate" "$METADATA_FILE" | head -n 1)

mkdir -p "$OUTPUT_DIR/saml/certs"
openssl genpkey -algorithm RSA -out "$OUTPUT_DIR/saml/certs/private.key" -pkeyopt rsa_keygen_bits:2048
openssl req -new -key "$OUTPUT_DIR/saml/certs/private.key" -out "$OUTPUT_DIR/saml/certs/cert.csr" -subj $CERT_INFO
openssl x509 -req -days 365 -in "$OUTPUT_DIR/saml/certs/cert.csr" -signkey "$OUTPUT_DIR/saml/certs/private.key" -out "$OUTPUT_DIR/saml/certs/public.crt"

saml_cert=$(sed '/-----BEGIN CERTIFICATE-----/d; /-----END CERTIFICATE-----/d' "$OUTPUT_DIR/saml/certs/public.crt" | tr -d '\n')
private_key=$(sed '/-----BEGIN PRIVATE KEY-----/d; /-----END PRIVATE KEY-----/d' "$OUTPUT_DIR/saml/certs/private.key" | tr -d '\n')


echo "Extracted values:"
echo "entityId: $entityId"
echo "ssoUrl: $ssoUrl"
echo "sloUrl: $sloUrl"
echo "x509cert: $x509cert"
echo "saml_cert: $saml_cert"
echo "private_key: $private_key"

echo "Updating settings.json..."
jq --arg sp_entityId "https://$SP_DOMAIN/metadata/" \
   --arg acs_url "https://$SP_DOMAIN/?acs" \
   --arg slo_url_sp "https://$SP_DOMAIN/?sls" \
   --arg nameIdFormat "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" \
   --arg sp_x509cert "$saml_cert" \
   --arg sp_privateKey "$private_key" \
   --arg idp_entityId "$entityId" \
   --arg sso_url "$ssoUrl" \
   --arg slo_url "$sloUrl" \
   --arg idp_x509cert "$x509cert" \
   '.sp.entityId = $sp_entityId | .sp.assertionConsumerService.url = $acs_url | .sp.singleLogoutService.url = $slo_url_sp | .sp.NameIDFormat = $nameIdFormat | .sp.x509cert = $sp_x509cert | .sp.privateKey = $sp_privateKey | .idp.entityId = $idp_entityId | .idp.singleSignOnService.url = $sso_url | .idp.singleLogoutService.url = $slo_url | .idp.x509cert = $idp_x509cert' \
    "$SETTINGS_FILE" > "${SETTINGS_FILE}.tmp" && mv "${SETTINGS_FILE}.tmp" "$SETTINGS_FILE"
#   "$SETTINGS_FILE" > "$OUTPUT_DIR/saml/settings.json"

echo "Updated settings.json:"
