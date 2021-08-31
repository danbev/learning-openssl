### TLS 1.3 notes

### Inspecting the transport protocol
This section contains an example of inpecting the TLS 1.3 transport protocol
which can be helpful while reading the spec to get a better understanding of
the various packets and communications going on.

First create a key and a certificate:
```console
$ openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

Then we can start the server:
```console
$ openssl s_server -crlf -tls1_3 -msg -key key.pem -cert cert.pem -keylogfile keylogfile
Using default temp DH parameters
ACCEPT
```

And the then client:
```console
$ openssl s_client -crlf -tls1_3 -msg -keylogfile keylogfile localhost
```

### ClientHello
Key Exchange is performed using the ClientHello and ServerHello messages
which establish the key sharing material. All messages communicated after
this stage are encrypted:
```
Client                              Server
ClientHello  {                      
  key_share             ----------> ServerHello {
  signature_algoritms                 key_share   
  psk_key_exchange_modes              pre_shared_key
  pre_shared_key                    }
}
```

So the first thing that happens is that the client sends a ClientHello to the
server. This struct is definded as:
```
      uint16 ProtocolVersion;
      opaque Random[32];

      uint8 CipherSuite[2];    /* Cryptographic suite selector */

      struct {
          ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
          Random random;
          opaque legacy_session_id<0..32>;
          CipherSuite cipher_suites<2..2^16-2>;
          opaque legacy_compression_methods<1..2^8-1>;
          Extension extensions<8..2^16-1>;
      } ClientHello;
```
And we can see an example of an actual packet below which is sent in clear text:
```text
Transmission Control Protocol, Src Port: 33540, Dst Port: 7777, Seq: 1, Ack: 1, Len: 217
Transport Layer Security
    TLSv1.3 Record Layer: Handshake Protocol: Client Hello
        Content Type: Handshake (22)
        Version: TLS 1.0 (0x0301)
        Length: 212
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Length: 208
            Version: TLS 1.2 (0x0303)
            Random: a81144f062dc7072dcf4edcb379b4639eaf123397e8d02b4…
            Session ID Length: 32
            Session ID: 0dc04a44929c950d5b2fc09d02e3a9c8e441014e9f8019af…
            Cipher Suites Length: 10
            Cipher Suites (5 suites)
                Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
                Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
                Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
                Cipher Suite: TLS_AES_128_CCM_SHA256 (0x1304)
                Cipher Suite: TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)
            Compression Methods Length: 1
            Compression Methods (1 method)
            Extensions Length: 125
            Extension: ec_point_formats (len=4)
            Extension: supported_groups (len=12)
            Extension: session_ticket (len=0)
            Extension: encrypt_then_mac (len=0)
            Extension: extended_master_secret (len=0)
            Extension: signature_algorithms (len=30)
                Type: signature_algorithms (13)
                Length: 30
                Signature Hash Algorithms Length: 28
                Signature Hash Algorithms (14 algorithms)
            Extension: supported_versions (len=3)
            Extension: psk_key_exchange_modes (len=2)
                Type: psk_key_exchange_modes (45)
                Length: 2
                PSK Key Exchange Modes Length: 1
                PSK Key Exchange Mode: PSK with (EC)DHE key establishment (psk_dhe_ke) (1)
            Extension: key_share (len=38)
                Type: key_share (51)
                Length: 38
                Key Share extension
                    Client Key Share Length: 36
                    Key Share Entry: Group: x25519, Key Exchange length: 32
                        Group: x25519 (29)
                        Key Exchange Length: 32
                        Key Exchange: 9e1f52f540dbafe12a4112557ca1c34855f2c51f2f318d79…

```
Notice that `Version` is set to v1.2 which and was used in versions prior to
1.3 for version negotiation. But this is not used in 1.3 in which version
perference is handled in the extension supported_version. This fields is still
required so that a server that supports 1.2 can still parse the client hello
and not think that it is invalid. Also keeping these fields will allow for
these packages to traverse middleware boxes which might otherwise not allow them
as they probably don't recognize the version being used.

`random` should be created by a cryptographically secure pseudorandom number
generator (CSPRNG) and is used as keying material.

`Session ID` was used with versions prior to 1.3 for session resumption. In 1.3
`Pre-Shared Key (PKS)` is used instead (See section below).

`Compression Methods` is required but not used in 1.3 which instead uses an
extension.
There are fields that are in the packet format but not used are required for
backward compatability with 1.2. A client might want to communicate using tls1.3
but the server might only support 1.2 and this way the 1.2 server will still be
able to interpret the packet. 

### Cipher suites
The format of the cipher suites strings is as follows:
```text
CipherSuite TLS_AEAD_HASH = VALUE;
```
TLS is the protocol.
AEAD is the algoritm used for record protection.
HASH is the algorithm used for HKDF

The following cipher suites are defined by the spec:
* TLS_AES_128_GCM_SHA256
* TLS_AES_256_GCM_SHA384
* TLS_CHACHA20_POLY1305_SHA256
* TLS_AES_128_CCM_SHA256
* TLS_AES_128_CCM_8_SHA256

```text
Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
```
So in this case AEAD would be AES_256_GCM.


### Pre-Shared Key (PSK)
TLS usually uses public key certificates for authentication but it is possible
for the protocol to use symmetric keys that are shared in advanced to establish
the TLS connection. This can be useful on devices with limited CPU power. 

PSK can also be used for session resumption after a  successful handshake the
server can send PSK identity derived from the intitial handshake. A client may
then use this value in new handshakes in the extension `pre_shared_key`.

### pre_shared_key
If the client send this extension it must also send `psk_key_exchange_modes`
```text
Transport Layer Security
    TLSv1.3 Record Layer: Handshake Protocol: Client Hello
        ...
        Handshake Protocol: Client Hello
	    ...
            Compression Methods (1 method)
            Extension: psk_key_exchange_modes (len=2)
                Type: psk_key_exchange_modes (45)
                Length: 2
                PSK Key Exchange Modes Length: 1
                PSK Key Exchange Mode: PSK with (EC)DHE key establishment (psk_dhe_ke) (1)
```
* `psk_dhe_ke` In this case the client and the server must supply `key_share`.
* `psk_ke` in  In this mode the server must not supply `key_share`.




The server will choose one of the Cipher Suites that the client suggests. In
our case this is:
```
Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```
`TLS` is the protocol.
`EDCHE` is the key exchange algorithm.
`RSA` is the authentication algorithm.
`AES_256_CBC` is the bulk encryption algorithm. 
SHA` is the message authentication algorithm.

#### Extension fields
This struct is dedfined in the spec as follows:
```text
    struct {
        ExtensionType extension_type;
        opaque extension_data<0..2^16-1>;
    } Extension;

    enum {
        server_name(0),                             /* RFC 6066 */
        max_fragment_length(1),                     /* RFC 6066 */
        status_request(5),                          /* RFC 6066 */
        supported_groups(10),                       /* RFC 8422, 7919 */
        signature_algorithms(13),                   /* RFC 8446 */
        use_srtp(14),                               /* RFC 5764 */
        heartbeat(15),                              /* RFC 6520 */
        application_layer_protocol_negotiation(16), /* RFC 7301 */
        signed_certificate_timestamp(18),           /* RFC 6962 */
        client_certificate_type(19),                /* RFC 7250 */
        server_certificate_type(20),                /* RFC 7250 */
        padding(21),                                /* RFC 7685 */
        pre_shared_key(41),                         /* RFC 8446 */
        early_data(42),                             /* RFC 8446 */
        supported_versions(43),                     /* RFC 8446 */
        cookie(44),                                 /* RFC 8446 */
        psk_key_exchange_modes(45),                 /* RFC 8446 */
        certificate_authorities(47),                /* RFC 8446 */
        oid_filters(48),                            /* RFC 8446 */
        post_handshake_auth(49),                    /* RFC 8446 */
        signature_algorithms_cert(50),              /* RFC 8446 */
        key_share(51),                              /* RFC 8446 */
        (65535)
    } ExtensionType;
```

### supported_groups
Are sent by the client (Client Hello) and specifies the named groups that the
client supports for key exchange. This was called elliptic_curves in versions
prior to 1.3 and would only allow elliptic curves. But supported_groups could
also be Finite Field Diffie-Hellman parameters (or Elliptic Curve Diffie-Hellman
parameters).

Example:
```text
        Handshake Protocol: Client Hello
            ...
            Compression Methods (1 method)
            Extensions Length: 125
            Extension: supported_groups (len=12)
                Type: supported_groups (10)
                Length: 12
                Supported Groups List Length: 10
                Supported Groups (5 groups)
                    Supported Group: x25519 (0x001d)
                    Supported Group: secp256r1 (0x0017)
                    Supported Group: x448 (0x001e)
                    Supported Group: secp521r1 (0x0019)
                    Supported Group: secp384r1 (0x0018)
```

### key_share
This extension contains the client public key parameters. Since this will be
a Diffie-Hellman "family" the client can generate and send g^a mod n to the
server. The server will also send  a `key_share` and both will be able to
calculate a master secret. This is explained in [dh.md](./dh.md).

```text
Client                Public                        Server
a (number < n)        g (generator, small prime)    b (number < n)
                      n (big prime number)

A = g^a mod n                                        B =  g^b mod n
                        A (key_exchange) 
                     ------------------>
                        B (key_exchange)
                     <------------------

K_ab = (B)^a mod n                                   K_ab = (A)^b mod n
```
One thing to note is that at this stage the client is guessing/hopeing that the
server will accept the same key exchange method. If the server does not the
server will send RetryHelloRequest to restart the key share.
```text
            Extension: key_share (len=38)
                Type: key_share (51)
                Length: 38
                Key Share extension
                    Client Key Share Length: 36
                    Key Share Entry: Group: x25519, Key Exchange length: 32
                        Group: x25519 (29)
                        Key Exchange Length: 32
                        Key Exchange: 9e1f52f540dbafe12a4112557ca1c34855f2c51f2f318d79…
```
The group in this case is an elliptic curve and above we see that Curve25519 is
specified by the client (this is also the default in OpenSSL).
The group references one of the groups specified in the supported_groups
extension.


### ServerHello
This is the servers part of the key exchange.
```text
Transport Layer Security
    TLSv1.3 Record Layer: Handshake Protocol: Server Hello
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 122
        Handshake Protocol: Server Hello
            Handshake Type: Server Hello (2)
            Length: 118
            Version: TLS 1.2 (0x0303)
            Random: 46541d21a5a9ecaca2a1686767b920afa9e72c0faa466737…
            Session ID Length: 32
            Session ID: 0dc04a44929c950d5b2fc09d02e3a9c8e441014e9f8019af…
            Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
            Compression Method: null (0)
            Extensions Length: 46
            Extension: supported_versions (len=2)
                Type: supported_versions (43)
                Length: 2
                Supported Version: TLS 1.3 (0x0304)
            Extension: key_share (len=36)
                Type: key_share (51)
                Length: 36
                Key Share extension
                    Key Share Entry: Group: x25519, Key Exchange length: 32
                        Group: x25519 (29)
                        Key Exchange Length: 32
                        Key Exchange: 163cf1b4007dec0a36c875c86a96af7912d3e1928370c190…
    TLSv1.3 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec
    TLSv1.3 Record Layer: Handshake Protocol: Encrypted Extensions
    TLSv1.3 Record Layer: Handshake Protocol: Certificate
    TLSv1.3 Record Layer: Handshake Protocol: Certificate Verify
    TLSv1.3 Record Layer: Handshake Protocol: Finished
```
Now, the `Random` is somewhat overloaded and can be used for downgrade
protection. In the case where a 1.3 server detects that the ClientHello only
supports version 1.2 then the 1.3 server will add the following 8 bytes as the
last in the Random field:
```
44 4F 57 4E 47 52 44 01
and for version 1.1:
44 4F 57 4E 47 52 44 00
```
A TLS1.3 client that specifies in its ClientHello that it supports 1.3 and send
that to a 1.3 server, but the server's replied with a ServerHello that specifies
one of the above values in the Random field, that is it wants to downgrade. This
is possibly someone in the middle trying a downgrade attack and something that
the TLS1.3 will detect by checking for these values and aborting the connection.

The session id is not used and if we look we can see that it is just the same
value as the client sent:
```text
    Client Session ID: 0dc04a44929c950d5b2fc09d02e3a9c8e441014e9f8019af…

    Server Session ID: 0dc04a44929c950d5b2fc09d02e3a9c8e441014e9f8019af…
```

### HelloRetryRequest
If the server is not able accept a handshake, it will send a HelloRetryRequest
that describes the failure. The message is identical to the ServerHello in
structure and reuses the Random field to indicate that this is a
HelloRetryRequest.
```text
CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
```
If the Random field has the above value then the client knows that this is a
HelloRetryRequest (if not it's a ServerHello).


#### Configure Wireshark
We can configure wireshark to use the above specified `keylogfile` by going
into *Preferences* -> *Protocols* -> *TLS* and adding that file as the
`(Pre)-Master-Secret log filename`. This will allow us to see the decrypted
package contents.
