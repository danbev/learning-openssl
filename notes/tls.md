### TLS
In the TLS protocol the Record Layer takes care of transporting and encryption
and extensions handle other aspects (for example server name SNI).

There are four subprotocols:
#### Handshake protocol
In a full handshake the client and server will exchange capabilities and agree
on connection parameters. Validation of certificates will take place.
Both parties will agree on a master secret to be used to protect the session.
```
Client                                      Server
  ClientHello      --------------------->
                   <---------------------  ServerHello
                   [<--------------------  Certificate]
                   [<--------------------  ServerKeyExchange]
                   <---------------------  ServerHelloDone
  ClientKeyExchange--------------------->
  [ChangeCipherSpec--------------------->]
  Finished         --------------------->
                   [<--------------------  ChangeCipherSpec]
                   <--------------------   Finished
```

### ClientHello
Is the first message sent in a new Handshake
Lets take a look at a client hello. This was sent by invoking a test in node.js:
```console
$ env NODE_DEBUG_NATIVE=tls ./node test/parallel/test-tls-session-cache.js
```
Using wireshark we can inspect the ClientHello message:
```
Transport Layer Security
    TLSv1 Record Layer: Handshake Protocol: Client Hello
        Content Type: Handshake (22)
        Version: TLS 1.0 (0x0301)
        Length: 109
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Length: 105
            Version: TLS 1.0 (0x0301)
            Random: 35e6a7452268dbdb04cd4398f62946f38b21ca142993a269…
            Session ID Length: 0
            Cipher Suites Length: 18
            Cipher Suites (9 suites)
                Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
                Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
                Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
                Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
                Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
                Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
                Cipher Suite: TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)
            Compression Methods Length: 1
            Compression Methods (1 method)
            Extensions Length: 46
            Extension: server_name (len=10)
            Extension: ec_point_formats (len=4)
            Extension: supported_groups (len=12)
            Extension: encrypt_then_mac (len=0)
            Extension: extended_master_secret (len=0)
```
Notice the cipher suites being sent from the client to the server. And the client
is using TLS 1.0.

A cipher suite is a complete set of algorithms that are needed for a secure a
connection in TLS. This includes a key exchange algorithm, an authentication
algorithm, bulk encryption algorithm, and a message authentication algorithm.
```
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
```
Here `TLS` is the protocol. `EDCHE` is the key exchange algorithm. `RSA` is the
authentication algorithm. `AES_256_CBC` is the bulk encryption algorithm. `SHA`
is the message authentication algorithm.

The client sends the ciphers suites that it supports to the server as we can
see above and the servers responds with a chosen suite that it supports. If the
server does not have a match a secure connection will not be established.

#### Change cipher spec protocol
TODO

#### Application data protocol
TODO

#### Alert protocol
TODO
