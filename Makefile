sinclude config.mk

OPENSSL_PREFIX?=	/usr

OPENSSL_SRC?=

OPENSSL_INC?=	$(OPENSSL_PREFIX)/include
OPENSSL_LIB?=	$(OPENSSL_PREFIX)/lib

# Mute clang color-based warnings.
#CFLAGS+=	-fno-color-diagnostics
CFLAGS+=	-Wall -g -O0 -I$(OPENSSL_INC)
CFLAGS+=	-std=c99

LDLIBS+=	-lcrypto -lssl

LDFLAGS=	-L$(OPENSSL_LIB) -L$(OPENSSL_LIB)/ossl-modules
LDFLAGS+=	-Wl,-rpath,$(OPENSSL_LIB) -Wl,-rpath,$(OPENSSL_LIB)/ossl-modules

RM?=	rm -f

CPP_FILES+=	asn1.i
CPP_FILES+=	err.i

PROGS+=	array-overflow
PROGS+=	asn1
PROGS+=	basic
PROGS+=	bignum
PROGS+=	bio
PROGS+=	bio_in_mem
PROGS+=	bio_in_mem_nodejs
PROGS+=	bio_read_file
PROGS+=	bio_ssl
PROGS+=	decoder
# XXX: dh segfaults with 3.0.9.
#PROGS+=	dh
PROGS+=	dh_1_1_1
PROGS+=	distribution
PROGS+=	digest
PROGS+=	dsa
PROGS+=	ec
PROGS+=	ec-keygen
PROGS+=	err
ifneq ($(OPENSSL_SRC),)
# XXX: requires internal headers; doesn't compile with prebuilt binary packages.
PROGS+=	evp-pkey
endif
# XXX: does not compile/link (bad symbols).
PROGS+=	fips-provider
PROGS+=	generator
PROGS+=	hash
PROGS+=	hmac
PROGS+=	is_fips_enabled
PROGS+=	keymgmt
PROGS+=	pem_key_read
PROGS+=	private
PROGS+=	provider
PROGS+=	rand
PROGS+=	rand_status
PROGS+=	rsa
PROGS+=	rsa_data_too_large
PROGS+=	rsa_pss
PROGS+=	rsa_sign
PROGS+=	store
PROGS+=	x509
PROGS+=	random_bytes
PROGS+=	socket
PROGS+=	sign
PROGS+=	ssl
PROGS+=	wrong-tag
PROGS+=	wrong-tag2

LIBS+=	libcprovider.so
LIBS+=	libengine.so

asn1.i:	asn1.c

WNO_ERROR_DEPRECATED=	-Wno-error=deprecated

array-overflow.o: src/array-overflow.c
	$(COMPILE.c) $<

dh:	CFLAGS+=	$(WNO_ERROR_DEPRECATED)
ec:	CFLAGS+=	$(WNO_ERROR_DEPRECATED)
ec-keygen: LDLIBS+=	-lpthread

engine.o: CFLAGS+=	-fPIC
libengine.so: engine.o
	$(CC) -shared -fPIC $(CFLAGS) $(LDFLAGS) -o $@ $^

err.i: err.c

%.i: %.c
	$(CC) -E $(CFLAGS) $(OUTPUT_OPTION) $<

%.i: %.cc
	$(CXX) -E $(CXXFLAGS) $(OUTPUT_OPTION) $<

evp-pkey: CFLAGS+=	$(WNO_ERROR_DEPRECATED)

keymgmt: LDLIBS+=	-lpthread

cprovider.o:	CFLAGS+=	-fPIC -I.
libcprovider.so: cprovider.o
	$(CC) -shared -fPIC $(CFLAGS) $(LDFLAGS) -o $@ $^

.DEFAULT: all
all: $(CPP_FILES) $(LIBS) $(PROGS)

.PHONY: run
run: $(PROGS)
	for prog in $(PROGS); do \
		printf "%s ...\n" "$$prog"; \
		./$$prog; \
	done; \
	./test_engine.sh

.PHONY: clean
clean:
	$(RM) $(CPP_FILES)
	$(RM) $(LIBS)
	$(RM) $(PROGS)
	$(RM) *.o
