## Node.js TLS Renegotiation attach issue
This was discovered when linking against the latest openssl/openssl upstream
master:
```console
$ ~/work/security/openssl_build_master/bin/openssl version -b -v
OpenSSL 3.0.0-alpha17-dev  (Library: OpenSSL 3.0.0-alpha17-dev )
built on: Thu May 20 06:50:13 2021 UTC
```

The test in question is `test-https-client-renegotiation-limit.js` which
fails with the following error:
```console
$ out/Release/node /home/danielbevenius/work/nodejs/node-debug/test/parallel/test-https-client-renegotiation-limit.js
Caught exception: Error [ERR_TLS_SESSION_ATTACK]: TLS session renegotiation attack detected
Caught exception: Error [ERR_TLS_SESSION_ATTACK]: TLS session renegotiation attack detected
node:events:342
      throw er; // Unhandled 'error' event
      ^

Error: 00305ED07A7F0000:error:0A000153:SSL routines:ssl3_read_bytes:no renegotiation:ssl/record/rec_layer_s3.c:1604:

Emitted 'error' event on ClientRequest instance at:
    at TLSSocket.socketErrorListener (node:_http_client:447:9)
    at TLSSocket.emit (node:events:377:35)
    at TLSSocket._emitTLSError (node:_tls_wrap:908:10)
    at TLSWrap.onerror (node:_tls_wrap:429:11) {
  library: 'SSL routines',
  reason: 'no renegotiation',
  code: 'ERR_SSL_NO_RENEGOTIATION'
}
```
Lets start by finding out where this OpenSSL error is raised. This error is
defined in ssl/ssl_err.c:
```c
static const ERR_STRING_DATA SSL_str_reasons[] = {
    ...
    {ERR_PACK(ERR_LIB_SSL, 0, SSL_R_NO_RENEGOTIATION), "no renegotiation"},
    ...
}
```
And we can search for SSL_R_NO_RENEGOTIATION.
One place where this error is raised is in ssl/record/rec_layer_s3.c:
```c
int ssl3_read_bytes(SSL *s, int type, int *recvd_type, unsigned char *buf,          
                    size_t len, int peek, size_t *readbytes)                    
{
   ...
   } else if (alert_descr == SSL_AD_NO_RENEGOTIATION) {
            /*
             * This is a warning but we receive it if we requested
             * renegotiation and the peer denied it. Terminate with a fatal
             * alert because if application tried to renegotiate it
             * presumably had a good reason and expects it to succeed. In
             * future we might have a renegotiation where we don't care if
             * the peer refused it where we carry on.
             */
            SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_NO_RENEGOTIATION);
            return -1;
    }
}
```
Lets start with that:
```console
$ lldb -- out/Debug/node /home/danielbevenius/work/nodejs/node-debug/test/parallel/test-https-client-renegotiation-limit.js
(lldb) br s -f rec_layer_s3.c -l 1604
```
This breakpoint gets hit.

The OpenSSL Commit 55373bfd41 introduced `SSL_OP_ALLOW_CLIENT_RENEGOTIATION`
```text
* Client-initiated renegotiation is disabled by default. To allow it, use
  the -client_renegotiation option, the SSL_OP_ALLOW_CLIENT_RENEGOTIATION
  flag, or the "ClientRenegotiation" config parameter as appropriate.
```
Adding this option to src/crypto/crypto_context.cc in SecureContext::Init will
allow this test to pass:
```c++
SSL_CTX_set_options(sc->ctx_.get(), SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
```
I'm not sure this is something we want to do though.

