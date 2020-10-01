### Abstract Syntax Notation One (ASN.1)
It's goal is to describe the interface between two entities exchanging
information. Is used in X.509 (SSL, HTTPS), LDAP, VoIP, SNMP, LTE (3G, 4G).

Has been a standard since 1984!

#### Basic syntax
* Comments start with '--' and end with a matching '--' or end of line.
* Is case senstive. 
* Keywords start with capital letters.
* Underscore cannot be used in identifiers or keywords  
* Assignments use ::= (similar to what can be used in Make files)

Strings can be Character strings "bajja", Binary strings '1010'B or
Hexadecimal strings '1a'H.

#### Module
A module is the top level container
```
TestModule DEFINITIONS ::= {
  Age ::= INTEGER (0..120) DEFAULT 45
  Tired ::= BOOLEAN
}
```
The types we can use in an ans1 module are BOOLEAN, INTEGER, ENUMERATED, REAL
and NULL (information is missing/absent).
When we have our type set up we can use tools to turn the abstract data into
a bit stream. The bit stream can be of different formats, like Basic Encoding
Rule (BER) for example.

#### Basic Encoding Rule (BER)
Defines how the values defined in asn1 should be translated into bytes and
from bytes into asn1 (encoding/decoding).

Identifier:
```
{joint-iso-itu-t(2) asn1(1) base-encoding(1)}
```
```
+--------------------------------------------------------+
| Type   | Length |             Value                    |
+--------------------------------------------------------+
```
Type (one byte:
```
7        6 5      4                                      0
+--------------------------------------------------------+
| Class   | From |             Tag                       |
+--------------------------------------------------------+

Class:
00 = UNIVERSAL
01 = APPLICATION
10 = Context-Specific
11 = Private

Form:
0 = Primitive (no subtypes)
1 = Constructed (contains subtypes)

Tag:
1 = BOOLEAN
2 = INTEGER
3 = BIT STRING
4 = OCTET STRING
5 = NULL
6 = OBJECT_IDENTIFIER
9 = REAL
10 = SEQUENCE (OF)
16 = IASTRING
1A = VisibleString
```

### Privacy Enhanced Email (PEM)
Is a base64 (binary-to-text encoding) translation of BER/DER asn1.


### ASN1 in OpenSSL
There is an example in [asn1.c](../asn1.c) which is being used for exploring
asn1 funtionality. There are macros in this file that are used internally in
OpenSSL which are really just used at the moment to see what is generated in
isolation.

To run asn1.c through the preprocessor the following target can be used:
```console
$ make asn1_prep
```

This will generate the following code:
```c
static const ASN1_AUX something_aux = {
  ((void *)0), 0, 0, 0, something_cb, 0, ((void *)0)
};

static const ASN1_TEMPLATE something_seq_tt[] = {
  { (0), (0), __builtin_offsetof ( something , age) , "age", (ASN1_INTEGER_it) }
};

const ASN1_ITEM * something_it(void) {
  static const ASN1_ITEM local_it = {
    0x1, 16, something_seq_tt, sizeof(something_seq_tt) / sizeof(ASN1_TEMPLATE), &something_aux, sizeof(something), "something" };
  return &local_it;
}

something *d2i_something(something **a, const unsigned char **in, long len) {
  return (something *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, (something_it()));
}

int i2d_something(const something *a, unsigned char **out) {
  return ASN1_item_i2d((const ASN1_VALUE *)a, out, (something_it()));
}

something *something_new(void) {
  return (something *)ASN1_item_new((something_it()));
}

void something_free(something *a) {
  ASN1_item_free((ASN1_VALUE *)a, (something_it()));
}

```
