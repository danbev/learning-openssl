OPENSSL_DIR=../openssl_build_master
OPENSSL_BIN=${OPENSSL_DIR}/bin
export LD_LIBRARY_PATH=${OPENSSL_DIR}/lib
${OPENSSL_BIN}/openssl s_server -key test.key -cert test.crt -pass "pass:test" -port 7777 
