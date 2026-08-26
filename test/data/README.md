# Test certificates

`cert.pem` and `cert2.pem` are self-signed RSA-3072 certificates used as
public-key encryption recipients. Each file holds the private key followed by
the certificate, which is the layout `openssl_pkcs7_decrypt()` expects.

Two distinct certificates are required: a test that a recipient is matched by
its own key cannot fail when every entry decrypts with the same key.

Regenerate either with:

```bash
openssl req -x509 -nodes -days 3650 -newkey rsa:3072 -keyout cert.pem -out cert.pem
```

Both certificates expire 2036-08-23.
