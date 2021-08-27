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
$ openssl s_client -crlf -msg -keylogfile keylogfile localhost
```

#### Configure Wireshark
We can configure wireshark to use the above specified `keylogfile` by going
into *Preferences* -> *Protocols* -> *TLS* and adding that file as the
`(Pre)-Master-Secret log filename`. This will allow us to see the decrypted
package contents.
