### Abstract Syntax Notation One (ASN.1)
It's goal is to describe the interface between two entities exchanging
information. Is used in X.509 (SSL, HTTPS), LDAP, VoIP, SNMP, LTE (3G, 4G).

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

#### BER
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
