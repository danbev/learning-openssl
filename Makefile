OPENSSL_DIR=/Users/danielbevenius/work/security/openssl
OPENSSL_INCLUDE_DIR=$(OPENSSL_DIR)/include

basic: basic.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_DIR) -lcrypto

socket: socket.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_DIR) -lcrypto

ssl: ssl.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_DIR) -lcrypto -lssl

.PHONY: clean 

clean: 
	@rm -f basic socket ssl
