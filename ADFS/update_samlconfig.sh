#!/bin/bash

OUTPUT_DIR="/root/adfs/saml"
METADATA_FILE="$OUTPUT_DIR/federationmetadata.xml"
SETTINGS_FILE="$OUTPUT_DIR/settings.json"
SP_DOMAIN=$(hostname)

entityId=$(xmlstarlet sel -N md=$namespace -t -v "//md:EntityDescriptor/@entityID" "$METADATA_FILE")
ssoUrl=$(xmlstarlet sel -N md=$namespace -t -v "//md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location" "$METADATA_FILE")
sloUrl=$(xmlstarlet sel -N md=$namespace -t -v "//md:IDPSSODescriptor/md:SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location" "$METADATA_FILE")
x509cert=$(xmlstarlet sel -N md="urn:oasis:names:tc:SAML:2.0:metadata" -N ds="http://www.w3.org/2000/09/xmldsig#" -t -v "//md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate" "$METADATA_FILE" | head -n 1)

mkdir -p "$OUTPUT_DIR/certs"
openssl genpkey -algorithm RSA -out "$OUTPUT_DIR/certs/private.key" -pkeyopt rsa_keygen_bits:2048
openssl req -new -key "$OUTPUT_DIR/certs/private.key" -out "$OUTPUT_DIR/certs/cert.csr" -subj "/C=UA/ST=Kyiv/L=Kyiv/O=MyCompany/OU=MyUnit/CN=$SP_DOMAIN"
openssl x509 -req -days 365 -in "$OUTPUT_DIR/certs/cert.csr" -signkey "$OUTPUT_DIR/certs/private.key" -out "$OUTPUT_DIR/certs/public.crt"
saml_cert=$(cat "$OUTPUT_DIR/certs/public.crt")
private_key=$(cat "$OUTPUT_DIR/certs/private.key")

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
   "$SETTINGS_FILE" > "$OUTPUT_DIR/settings.json"

echo "Updated settings.json:"

