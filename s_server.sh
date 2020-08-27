OPENSSL_DIR=../openssl_build_master
OPENSSL_BIN=${OPENSSL_DIR}/bin
export LD_LIBRARY_PATH=${OPENSSL_DIR}/lib
#${OPENSSL_BIN}/openssl s_server -key test.key -cert test.crt -pass "pass:test" -port 7777 

${OPENSSL_BIN}/openssl s_server -cipher "RSA@SECLEVEL=0" -tls1 -debug -msg -security_debug_verbose -provider legacy -provider default -key rsa_private.pem -cert rsa_cert.crt -port 7777 
