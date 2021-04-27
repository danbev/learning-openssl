### Abstract Syntax Notation One (ASN.1)
The goal is to describe the interface between two entities exchanging
information. This enables the files/messages in this format to be used by
different languages.  Is used in X.509 (SSL, HTTPS), LDAP, VoIP, SNMP, LTE
(3G, 4G).

Is similar to ProtoBuf or Thrift which might have been used today but ASN1
has been a standard since 1984, and when the HTTPS spec, in 1994, was created
those protocols were not available.

ASN1 also contains serialization formats which specify ways to convert in-mem
data structures into a series of bytes. And from a series of bytes into
in-mem data structures.

#### Serialization formats
Distinguished Encoding Rules (DER) is used which is a variant of Basic Encoding
Rules (BER) but with restrictions that force the serialization to be identical
for certain types. For example a Boolean value in BER could be any of 255 non
zero values would be considered a true value and DER would only allow one
value. This is especially important for crypto where things like digital
signatures.

The DER encoded data format is often encoded as base64 which is called PEM.

#### Basic syntax
* Comments start with '--' and end with a matching '--' or end of line.
* Is case senstive. 
* Keywords start with capital letters.
* Underscore cannot be used in identifiers or keywords  
* Assignments use ::= (similar to what can be used in Make files)

Strings can be Character strings "bajja", Binary strings '1010'B or
Hexadecimal strings '1a'H.


#### INTEGER
Just like normal integers but they can be any size which is great for things
like RSA keys.

#### Strings
There are many types of strings. These are not null terminated.

#### OBJECT IDENTIFIERS
Are globally unique sequences of integers and are mostly used to identify
standards, algoritms, certificate extensions, orgs, etc.
For example:
```
2.5 is the "Directory Service"
```
There is an online service that can be used to look up what an OID identifies:
http://oid-info.com/get/1.3.6.1.4.1.11129.

#### SEQUENCE
This is like struct in c.

#### SEQUENCE OF
This is like an array in c.

#### OPTIONAL
Fields of a SEQUENCE or a SET can be marked as option in which case they will
be missing from the binary stream.

#### DEFAULT
Fields of a SEQUENCE or a SET can be marked as DEFAULT and given a value which
will be assigned that value if no value was provided for that field

#### Encoding
Defines how the values defined in asn1 should be translated into bytes and
from bytes into asn1 (encoding/decoding).

The format is of Tag/Type, Length, Value. So first in the stream there will be
a type which is called a Tag, followed by the length of the value of that
type/tag, and that is followed by the value itself:
```
+--------------------------------------------------------+
| Type   | Length |             Value                    |
+--------------------------------------------------------+
```
For example an INTGER value of 5 could be encoded as:
```
Tag  Length  Value
02   03      01 00 05
```
Notice that the value contains more than just the 5, more on this later.

The Type/Tag is one byte (one byte):
```
7         5      4                                       0
+--------------------------------------------------------+
| Class   | Form |             Tag                       |
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
In OpenSSL these values can be found in include/openssl/asn1.h.

#### Module
A module is the top level container
```
TestModule DEFINITIONS ::= {
  Age ::= INTEGER (0..120) DEFAULT 45
  Tired ::= BOOLEAN
}
```
The types we can use in an asn1 module are BOOLEAN, INTEGER, ENUMERATED, REAL
and NULL (information is missing/absent).
When we have our type set up we can use tools to turn the abstract data into
a bit stream. The bit stream can be of different formats, like Basic Encoding
Rule (BER) for example.

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
Just a note about the naming of the functions generated. something_it creates
a new ASN1_ITEM (it = item). d2i_something converts from DER, which is the
binary format, to internal (i) C structure which in our case is struct something.

