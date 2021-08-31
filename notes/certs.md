## Certificate notes


## x509 certificates
Is defined in [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html).
This is a structured binary format which is made up of key-value pairs encoded
as [ANS.1](./asn1.md) and uses DER encoding rules. A certificate can be
distributed in this raw DER format but is not well suited for terminal
applications or emails so Privacy Enhanced Email (PEM) format is used which has
a base64 scheme for encoding binary data. This format allows for encoding the
binary data as text and to also contain boundries to signal the beginning and
end of encoding sections.

Really a certificate can be distributed in any format, it does not matter in
the end as the will represent the same thing in the end in ASN.1 DER format.

The certificate has two important pieces of info:
* the servers public key
* a digital signature that can verify the identity of the certificate's authority


### x509 app
To inspect a certificate:
```console
$ openssl x509 --in cert.pem -text -nocert
```
Example of inspecting a particual field:
```console
$ openssl x509 --in cert.pem -serial -nocert
serial=683DECB9FE65EFB7784CEA87AB17FE2ABC7C8C96
```

`nocert` is just to prevent the output of the certificate and only show the
serial number in this case.

