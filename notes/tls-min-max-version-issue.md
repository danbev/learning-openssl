## test-tls-min-max-version.j

```console
out/Debug/node --tls-min-v1.3 /home/danielbevenius/work/nodejs/openssl/test/parallel/test-tls-cli-min-version-1.3.js
test: U U TLSv1_2_method U U SSLv23_method U expect U ECONNRESET ERR_SSL_INTERNAL_ERROR
   (/home/danielbevenius/work/nodejs/openssl/test/parallel/test-tls-min-max-version.js:121:3)
client ECONNRESET
server ERR_SSL_NO_PROTOCOLS_AVAILABLE
node:assert:122
  throw new AssertionError(obj);
  ^

AssertionError [ERR_ASSERTION]: Expected values to be strictly equal:
+ actual - expected

+ 'ERR_SSL_NO_PROTOCOLS_AVAILABLE'
- 'ERR_SSL_INTERNAL_ERROR'
           ^
    at /home/danielbevenius/work/nodejs/openssl/test/parallel/test-tls-min-max-version.js:65:16
    at /home/danielbevenius/work/nodejs/openssl/test/common/index.js:379:15
    at /home/danielbevenius/work/nodejs/openssl/test/common/index.js:379:15
    at maybeCallback (/home/danielbevenius/work/nodejs/openssl/test/fixtures/tls-connect.js:97:7)
    at TLSSocket.<anonymous> (/home/danielbevenius/work/nodejs/openssl/test/fixtures/tls-connect.js:73:13)
    at TLSSocket.emit (node:events:378:20)
    at emitErrorNT (node:internal/streams/destroy:192:8)
    at emitErrorCloseNT (node:internal/streams/destroy:157:3)
    at processTicksAndRejections (node:internal/process/task_queues:81:21) {
  generatedMessage: true,
  code: 'ERR_ASSERTION',
  actual: 'ERR_SSL_NO_PROTOCOLS_AVAILABLE',
  expected: 'ERR_SSL_INTERNAL_ERROR',
  operator: 'strictEqual'
}
```

If we search for `NO_PROTOCOLS_AVAILABLE` we can find that this error is raised
in `ssl/statem/statem_lib.c`
```console
$ lldb -- out/Debug/node --tls-min-v1.3 /home/danielbevenius/work/nodejs/openssl/test/parallel/test-tls-cli-min-version-1.3.js
(lldb) br s -f statem_lib.c -l 104
(lldb) r
Process 1888614 stopped
* thread #1, name = 'node', stop reason = breakpoint 1.1
    frame #0: 0x00007ffff7ad5ce8 libssl.so.3`tls_setup_handshake(s=0x0000000006071750) at statem_lib.c:104:9
   92  	{
   93  	    int ver_min, ver_max, ok;
   94  	
   95  	    if (!ssl3_init_finished_mac(s)) {
   96  	        /* SSLfatal() already called */
   97  	        return 0;
   98  	    }
   99  	
   100 	    /* Reset any extension flags */
   101 	    memset(s->ext.extflags, 0, sizeof(s->ext.extflags));
   102 	
   103 	    if (ssl_get_min_max_version(s, &ver_min, &ver_max, NULL) != 0) {
-> 104 	        SSLfatal(s, SSL_AD_PROTOCOL_VERSION, SSL_R_NO_PROTOCOLS_AVAILABLE);
   105 	        return 0;
   106 	    }
   107 	
   108 	    /* Sanity check that we have MD5-SHA1 if we need it */
   109 	    if (s->ctx->ssl_digest_methods[SSL_MD_MD5_SHA1_IDX] == NULL) {
   110 	        int md5sha1_needed = 0;
   111 	
   112 	        /* We don't have MD5-SHA1 - do we need it? */
   113 	        if (SSL_IS_DTLS(s)) {
   114 	            if (DTLS_VERSION_LE(ver_max, DTLS1_VERSION))
   115 	                md5sha1_needed = 1;
   116 	        } else {
```
So we can see that this break point is indeed reached.


__work in progress__
