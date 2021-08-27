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
And we can see an example of an actual packet below:
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
perference is handled in the extension supported_version.
`random` should be created by a cryptographically secure pseudorandom number
generator (CSPRNG) and is used as keying material.

`Session ID` was used with versions prior to 1.3 for session resumption. In 1.3
`Pre-Shared Key (PKS)` is used instead (See section below).

`Compression Methods` is required but not used in 1.3 which instead uses an
extension.
The fields that are in the package format but not used are required for backward
compatability with 1.2. A client might want to communicate using tls1.3 but the
server might only support 1.2 and this way the 1.2 server will still be able to
interpret the package. In 1.3 this field but contain one byte set to zero.

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
After a successful handshake the server can send PSK identity derived from the
intitial handshake. A client may then use this value in new handshakes in the
extension `pre_shared_key`.


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
#### key_share

#### signature_algorithms

#### psk_key_exchange_modes

#### pre_shared_key

#### Configure Wireshark
We can configure wireshark to use the above specified `keylogfile` by going
into *Preferences* -> *Protocols* -> *TLS* and adding that file as the
`(Pre)-Master-Secret log filename`. This will allow us to see the decrypted
package contents.
