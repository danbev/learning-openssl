OPENSSL_DIR=../openssl_build_master
OPENSSL_BIN=${OPENSSL_DIR}/bin
export LD_LIBRARY_PATH=${OPENSSL_DIR}/lib
#${OPENSSL_BIN}/openssl s_client -key test.key -cert test.crt -pass "pass:test" -port 7777 
#${OPENSSL_BIN}/openssl s_client -tls1 -key test.key -cert test.crt -pass "pass:test" -port 7777 

${OPENSSL_BIN}/openssl s_client -security_debug_verbose -debug -msg -key rsa_private.pem -cert rsa_cert.crt -tls1 -port 7777 
