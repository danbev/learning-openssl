## Certificate notes


### Ceritificate Authority

### x509 certificates
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

The certificate contains:
* the servers public key
* a digital signature that can verify the identity of the certificate's authority
* meta data used by the CA

For example:
```console
$ openssl x509 --in cert.pem -text -nocert
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            68:3d:ec:b9:fe:65:ef:b7:78:4c:ea:87:ab:17:fe:2a:bc:7c:8c:96
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = SE, ST = Stockholm, L = Stockholm, O = Red Hat, OU = nodeshift, CN = localhost, emailAddress = daniel.bevenius@gmail.com
        Validity
            Not Before: Aug 27 07:05:50 2021 GMT
            Not After : Aug 27 07:05:50 2022 GMT
        Subject: C = SE, ST = Stockholm, L = Stockholm, O = Red Hat, OU = nodeshift, CN = localhost, emailAddress = daniel.bevenius@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:ca:af:5e:2c:46:a6:d3:f0:9b:74:43:f6:25:2a:
                    a4:ba:08:ee:dc:4b:2e:81:07:92:5f:36:57:4f:7d:
                    47:f0:87:fb:00:87:38:d4:43:c6:f9:19:c9:95:77:
                    f3:8b:f2:a7:c0:e7:b5:e6:15:20:0c:a5:e7:50:8a:
                    e0:76:12:5d:a1:fa:6e:4e:08:cd:4a:7b:e7:8e:78:
                    2f:13:ff:23:c4:18:6e:5d:c8:c2:de:25:be:6b:bb:
                    d5:91:39:9a:4e:6b:58:fb:17:43:b4:66:c3:24:3c:
                    66:e8:2e:49:a1:bc:93:a7:8d:14:41:08:ee:73:63:
                    ea:91:9b:f5:b1:67:b3:57:33:63:f1:37:d3:30:9b:
                    ba:80:26:2b:fc:9a:01:ff:8e:d1:f9:89:dd:2c:22:
                    c5:50:21:6a:cd:f2:43:09:2c:43:d7:5e:fc:79:7c:
                    5a:db:c2:7f:f6:fe:c7:9c:69:95:cf:23:59:aa:ba:
                    02:85:0b:2a:07:a6:28:71:74:7a:fa:df:c5:d1:42:
                    c1:51:37:36:83:8c:fd:9e:d0:7d:b3:d4:c1:7c:a8:
                    86:94:85:4c:06:40:45:91:ae:e0:2e:b4:e4:79:96:
                    2f:94:04:da:e9:8c:46:a9:95:9b:0c:f3:89:b1:32:
                    ef:09:d1:fc:ea:9a:e8:98:4f:15:fd:a3:1e:9a:b3:
                    fc:05
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                DC:45:D9:1A:F9:01:96:F8:4B:AF:BF:42:F2:E6:36:AA:23:1C:1A:1F
            X509v3 Authority Key Identifier: 
                keyid:DC:45:D9:1A:F9:01:96:F8:4B:AF:BF:42:F2:E6:36:AA:23:1C:1A:1F

            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         0c:23:28:e5:f6:c1:1b:b0:39:35:f2:e4:4a:ec:b7:ab:0b:03:
         ff:81:e0:7d:0d:d5:8c:78:55:50:e0:bd:5e:ee:80:ba:b6:36:
         f7:8f:a4:10:2a:9d:85:e6:6b:8d:b0:d1:85:3e:3b:d1:a5:1a:
         70:17:e3:be:1d:dd:7e:2c:29:e5:cb:e9:13:78:eb:cf:79:25:
         06:0c:2c:b5:b3:dc:6b:2e:65:b0:92:55:c6:e2:a0:ce:29:9f:
         f6:80:d3:88:3e:1a:f4:83:24:52:05:87:ca:04:8f:a2:83:f0:
         51:a2:30:bf:47:a4:58:24:c2:65:fa:1c:fa:e0:8a:13:c9:8e:
         12:6e:91:5a:88:42:4d:0e:ce:b6:dc:d5:4f:37:38:e7:d2:8d:
         56:e3:c7:42:91:ab:fd:bb:c1:4e:8e:51:35:26:94:80:f1:7e:
         a0:97:27:83:c7:19:2b:20:19:f3:29:4b:42:ee:72:45:04:04:
         e1:be:68:f7:41:ac:45:10:97:7a:fe:95:a8:95:2a:26:9b:ee:
         79:51:36:fb:63:e4:b1:bb:36:6c:b4:cc:41:e1:8c:44:69:3f:
         53:5e:1e:9e:32:87:57:af:ba:42:e0:e0:d5:fe:c8:ca:6e:71:
         5f:db:97:36:8b:5b:ed:95:20:24:d8:41:27:70:d5:ed:df:2f:
         07:80:d4:f0

```
This is a self-signed certificate and we can see that  by looking at the
`Issuer` field which is the same as the subject (our server in this case):
```console
$ openssl x509 --in cert.pem -issuer -nocert
issuer=C = SE, ST = Stockholm, L = Stockholm, O = Red Hat, OU = nodeshift, CN = localhost, emailAddress = daniel.bevenius@gmail.com

$ openssl x509 --in cert.pem -subject -nocert
subject=C = SE, ST = Stockholm, L = Stockholm, O = Red Hat, OU = nodeshift, CN = localhost, emailAddress = daniel.bevenius@gmail.com
```
Usually a CA will generate a hash of the subjects public key and then signing
that hash with the CA's private key. This signed hash value is the signature

The client will recieve the above certificate it can see that there is a public
key. The client also wants to verify that this public key actually belongs to
the server in question so it needs to validate.

The client needs to trust the CA that signed the signature in the certificate
and this is usually done adding the CA's public key to the clients trusted key
store. These trusted keys are usually provided by the operating system or by
a browers.

#### x509 app
To inspect a certificate:
```console
$ openssl x509 --in cert.pem -text -nocert
```
Example of inspecting a particular field:
```console
$ openssl x509 --in cert.pem -serial -nocert
serial=683DECB9FE65EFB7784CEA87AB17FE2ABC7C8C96
```
`nocert` is just to prevent the output of the certificate and only show the
serial number in this case.


### Verifying a certificate
In `src/certificate` there is directory with examples to verify a certificate
manually to understand the process.

First we extract the issuers public key into `issuer-pub.pem`:
```console
$ openssl x509 -in cert.pem -noout -pubkey > issuer-pub.pem
```
Extract the signature into `signature.txt`:
```console
$ openssl x509 -in cert.pem -text -noout -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame > signature.txt
```
Convert the signature hexdump (the format that is displayed above in the
Signature Algorithm field) as binary:
```console
$ cat signature.txt | xxd -r -p > signature.bin
```
This is doing the reverse of what xxd (a hex dumper) usually does. It usually
takes a file and outputs the hex values of it. In this case the signature is
already in hex and we want the reverse, hence the `-r` flag. We can verify this
using:
```console
 xxd -C signature.bin
00000000: 0c23 28e5 f6c1 1bb0 3935 f2e4 4aec b7ab  .#(.....95..J...
00000010: 0b03 ff81 e07d 0dd5 8c78 5550 e0bd 5eee  .....}...xUP..^.
00000020: 80ba b636 f78f a410 2a9d 85e6 6b8d b0d1  ...6....*...k...
00000030: 853e 3bd1 a51a 7017 e3be 1ddd 7e2c 29e5  .>;...p.....~,).
00000040: cbe9 1378 ebcf 7925 060c 2cb5 b3dc 6b2e  ...x..y%..,...k.
00000050: 65b0 9255 c6e2 a0ce 299f f680 d388 3e1a  e..U....).....>.
00000060: f483 2452 0587 ca04 8fa2 83f0 51a2 30bf  ..$R........Q.0.
00000070: 47a4 5824 c265 fa1c fae0 8a13 c98e 126e  G.X$.e.........n
00000080: 915a 8842 4d0e ceb6 dcd5 4f37 38e7 d28d  .Z.BM.....O78...
00000090: 56e3 c742 91ab fdbb c14e 8e51 3526 9480  V..B.....N.Q5&..
000000a0: f17e a097 2783 c719 2b20 19f3 294b 42ee  .~..'...+ ..)KB.
000000b0: 7245 0404 e1be 68f7 41ac 4510 977a fe95  rE....h.A.E..z..
000000c0: a895 2a26 9bee 7951 36fb 63e4 b1bb 366c  ..*&..yQ6.c...6l
000000d0: b4cc 41e1 8c44 693f 535e 1e9e 3287 57af  ..A..Di?S^..2.W.
000000e0: ba42 e0e0 d5fe c8ca 6e71 5fdb 9736 8b5b  .B......nq_..6.
$ cat signature.txt 
0c:23:28:e5:f6:c1:1b:b0:39:35:f2:e4:4a:ec:b7:ab:0b:03:
ff:81:e0:7d:0d:d5:8c:78:55:50:e0:bd:5e:ee:80:ba:b6:36:
f7:8f:a4:10:2a:9d:85:e6:6b:8d:b0:d1:85:3e:3b:d1:a5:1a:
70:17:e3:be:1d:dd:7e:2c:29:e5:cb:e9:13:78:eb:cf:79:25:
06:0c:2c:b5:b3:dc:6b:2e:65:b0:92:55:c6:e2:a0:ce:29:9f:
f6:80:d3:88:3e:1a:f4:83:24:52:05:87:ca:04:8f:a2:83:f0:
51:a2:30:bf:47:a4:58:24:c2:65:fa:1c:fa:e0:8a:13:c9:8e:
12:6e:91:5a:88:42:4d:0e:ce:b6:dc:d5:4f:37:38:e7:d2:8d:
56:e3:c7:42:91:ab:fd:bb:c1:4e:8e:51:35:26:94:80:f1:7e:
a0:97:27:83:c7:19:2b:20:19:f3:29:4b:42:ee:72:45:04:04:
e1:be:68:f7:41:ac:45:10:97:7a:fe:95:a8:95:2a:26:9b:ee:
79:51:36:fb:63:e4:b1:bb:36:6c:b4:cc:41:e1:8c:44:69:3f:
53:5e:1e:9e:32:87:57:af:ba:42:e0:e0:d5:fe:c8:ca:6e:71:
5f:db:97:36:8b:5b:ed:95:20:24:d8:41:27:70:d5:ed:df:2f:
07:80:d4:f0
```

```console
$ openssl rsautl -verify -inkey issuer-pub.pem -in signature.bin -pubin > signature-decrypted.bin
```

Now, we can parse the decrypted signature and inspect the hash:
```console
$ openssl asn1parse -inform der -in signature-decrypted.bin
    0:d=0  hl=2 l=  49 cons: SEQUENCE          
    2:d=1  hl=2 l=  13 cons: SEQUENCE          
    4:d=2  hl=2 l=   9 prim: OBJECT            :sha256
   15:d=2  hl=2 l=   0 prim: NULL              
   17:d=1  hl=2 l=  32 prim: OCTET STRING      [HEX DUMP]:BE0955F96C7C1FE2F73640D54BA3C9A2AE8583117F00EB411A4FCE3F643C84F9
```
So we, or the client rather, wants to know if this hash will match a hash
produced using the contents of the certificate (but not including the signature
field).
First we extract and store the body to a file:
```console
$ openssl asn1parse -in cert.pem -strparse 4 -out cert-body.bin -noout
```
And then we can check the digest using:
```console
$ openssl dgst -sha256 cert-body.bin
SHA256(cert-body.bin)= be0955f96c7c1fe2f73640d54ba3c9a2ae8583117f00eb411a4fce3f643c84f9
```
Then the client would compare these to hashes:
```text
BE0955F96C7C1FE2F73640D54BA3C9A2AE8583117F00EB411A4FCE3F643C84F9
be0955f96c7c1fe2f73640d54ba3c9a2ae8583117f00eb411a4fce3f643c84f9
```
So a CA would compute a HASH over the DER encoded public key section of the
certificate signing request, and then sign the hash with its own private key.
And when the client gets a certificate it can create a hash over the same data
in the certificate that was signed by the CA. The client uses the CA's public
key to try to decrypt the signature and then checks if the hashes match.


