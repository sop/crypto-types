# Elliptic Curve Keys for Unit Testing

Generate private key:

    openssl genpkey -out private_key.pem -algorithm EC \
      -pkeyopt ec_paramgen_curve:prime256v1 \
      -pkeyopt ec_param_enc:named_curve &&
    openssl ec -in private_key.pem -out ec_private_key.pem

Extract public key:

    openssl ec -out public_key.pem \
      -in private_key.pem -pubout
