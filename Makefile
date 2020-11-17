OPENSSL_DIR=/home/danielbevenius/work/security/openssl_build_master
OPENSSL_INCLUDE_DIR=$(OPENSSL_DIR)/include
OPENSSL_LIB_DIR=$(OPENSSL_DIR)/lib

CFLAGS=-g -O0 -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) \
     -L$(OPENSSL_LIB_DIR)/ossl-modules -lcrypto \
     -lpthread -lssl -Wl,-rpath,$(OPENSSL_LIB_DIR) 

CC := gcc

basic: basic.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto 

ssl_method: ssl_method.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto -lssl

hmac: hmac.c
	${CC} -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto

digest: digest.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto

sign: sign.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto

private: private.c
	${CC} -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto

socket: socket.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto

ssl: ssl.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto -lssl

engine: engine.c
	clang -O0 -g -fPIC -I$(OPENSSL_INCLUDE_DIR) -c $< -o $@.o
	clang -shared -o $@.so -L$(OPENSSL_LIB_DIR) -lcrypto $@.o

random_bytes: random_bytes.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto -lssl

bio: bio.c
	$(CC) $(CFLAGS)

bio_read_file: bio_read_file.c
	$(CC) $(CFLAGS)

bio_in_mem: bio_in_mem.c
	$(CC) $(CFLAGS)

bio_in_mem_nodejs: bio_in_mem_nodejs.c
	$(CC) $(CFLAGS)

asn1: asn1.c
	$(CC) $(CFLAGS)

.PHONY: err_pre
err_pre: CFLAGS=-g -O0 -I$(OPENSSL_INCLUDE_DIR) $< -E -o $@ -L$(OPENSSL_LIB_DIR) \
     -L$(OPENSSL_LIB_DIR)/ossl-modules -lcrypto \
     -lpthread -lssl -Wl,-rpath,$(OPENSSL_LIB_DIR) 
err_pre: err.c
	$(CC) $(CFLAGS)
	@echo "Generated $@."

err: err.c
	$(CC) $(CFLAGS)

.PHONY: asn1_prep
asn1_prep: CFLAGS=-g -O0 -I$(OPENSSL_INCLUDE_DIR) $< -E -o $@ -L$(OPENSSL_LIB_DIR) \
     -L$(OPENSSL_LIB_DIR)/ossl-modules -lcrypto \
     -lpthread -lssl -Wl,-rpath,$(OPENSSL_LIB_DIR) 
asn1_prep: asn1.c
	$(CC) $(CFLAGS)
	@echo "Generated $@."

wrong-tag: wrong-tag.c
	$(CC) $(CFLAGS)

bio_ssl: bio_ssl.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto -lssl

derive: derive.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto -lssl

distribution: distribution.cc
	clang++ -std=c++14 -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto -lssl

generator: generator.cc
	clang++ -std=c++14 -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto -lssl

ec: ec.c
	$(CC) $(CFLAGS)

ec-keygen: ec-keygen.c
	$(CC) $(CFLAGS)

rsa: rsa.c
	$(CC) $(CFLAGS)

rsa_pss: rsa_pss.c
	$(CC) $(CFLAGS)

dsa: dsa.c
	$(CC) $(CFLAGS)

provider: provider.c
	$(CC) $(CFLAGS)

fips-provider: fips-provider.c
	$(CC) $(CFLAGS)

rand: rand.c
	$(CC) $(CFLAGS)

store: store.c
	$(CC) $(CFLAGS)

hash: hash.c
	$(CC) $(CFLAGS)

pem_key_read: pem_key_read.c
	$(CC) $(CFLAGS)

store-info: store-info.c
	$(CC) $(CFLAGS)

decoder: decoder.c
	$(CC) $(CFLAGS)

keymgmt: keymgmt.c
	$(CC) $(CFLAGS)


.PHONY: clean 

clean: 
	@rm -f basic socket ssl engine hmac digest sign private random_bytes ssl_method derive
