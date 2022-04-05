### Padding
This document contains notes about padding used in crypto.

### RSA padding
Just to recap about RSA and that it will split the message into blocks of
plaintext. For example this could be 16 byte blocks (so 128 bits in total).
But the input message might not be an even multiple of this size so padding is
added to ensure this.

For example, if we need to pad on byte:
```
              7  6  5  4  3  2  1  0
Block size 8: DD OF 0F CB F1 AA 97
Padding     : DD OF 0F CB F1 AA 97 01
```
Two bytes:
```
              7  6  5  4  3  2  1  0
Block size 8: DD OF 0F CB F1 AA 97
Padding     : DD OF 0F CB F1 AA 02 02
```
And if more are needed they will be 03, 04 and so on. One situation that is
possible is that we have a valid 01 as the last character in which case a
complete padding byte is appended to the message:
```
              7  6  5  4  3  2  1  0  7  6  5  4  3  2  1  0
Block size 8: DD OF 0F CB F1 AA 97 01
Padding     : DD OF 0F CB F1 AA 97 01 08 08 08 08 08 08 08 08

                    Block n-1                       Block n
              7  6  5  4  3  2  1  0          7  6  5  4  3  2  1  0
            +--+--+--+--+--+--+--+--+       +--+--+--+--+--+--+--+--+
Ciphertext  |  |  |  |  |  |  |  | x|       |  |  |  |  |  |  |  |  |   
            +--+--+--+--+--+--+--+--+       +--+--+--+--+--+--+--+--+
                                   |                    |
                                   +----+                 Decrypt
                                        |               ↓ 
            +--+--+--+--+--+--+--+--+   |   +--+--+--+--+--+--+--+--+
            | ?| ?| ?| ?| ?| ?| ?| ?|   |   | ?| ?| ?| ?| ?| ?| ?| ?|   
            +--+--+--+--+--+--+--+--+   |   +--+--+--+--+--+--+--+--+
                                        |                          |
                                        +--------------------------+ ? ^ x = 01
                                                                   ↓
              7  6  5  4  3  2  1  0          7  6  5  4  3  2  1  0
            +--+--+--+--+--+--+--+--+       +--+--+--+--+--+--+--+--+
Plaintext   |  |  |  |  |  |  |  |  |       |  |  |  |  |  |  |  |01|   
            +--+--+--+--+--+--+--+--+       +--+--+--+--+--+--+--+--+

```
Notice that we are able to get the plain text of the last value in block n-1.
This is possible as the last block will first be decrypted and then it will be
xored with the previous ciphertext (which in this case we control). Now if we
can guess the value of x such that it equals 0x01. Doing this would make the
padding valied and no error reported by the oracle (server or whatever program
is decrypting the data).

### Optimal Asymmetric Encryption Padding (OAEP or sometimes RSA-OAEP).
For this we need the message to be encrypted `K` and two hash functions and also
a PRNG `R`.

The encoded message will be formed as:
```
M = H || 00 . . . 00 || 01 || K
```
So our message K needs to be small enough to fit into a byte array with h bytes
then as many 00 as needed (what are these for?) and then a 01 separator followed
by the message. But also notice that the final result will have a 00 prepended
to it.


This message is then processed like this:
```
   +---+        +-------------------+
   | R |        |H||0000...00001||K |   (as many 00 as required ending with 01)
   +---+        +-------------------+
     |   +-----+         |
     +-->|Hash1|-------->^
     |   +-----+         |
     |                   |
     |   +-----+         |
     ^<--|Hash1|<--------+
     |   +-----+         |
     ↓                   ↓
   +---+        +-------------------+
   | R |        |H||00000...0001||K |
   +---+        +-------------------+
     |
     +-----+    
           ↓
   +---------------------------------+
P= |00|      |                       |
   +---------------------------------+

P = 00 || M || R
```

```
m = 256 bytes for 2048-bit RSA
h = 32 SHA-256 as Hash2

m - n - 1
256 - 32 - 1 = 233 bytes for M

245 - 2*32 - 2 = 190 (bytes available for the message)
```
Remember we have two hash functions, therefore the *2. The -2 is for the 01
separator but I don't understand why this would be two and not one. There is
only one 01 separator as far as I can tell. What am I missing?

And I was not sure what `||` meant, but looking at the notation section in
https://tools.ietf.org/html/rfc3447#section-2 I see it means it's a
concatenation operator. This section is also useful if you come accross variable
names that might not be obvious at first in OpenSSL. 
Notice the 01 which is used as a separator above that is appended above which
is why we have to subtract two from M. I think this is due to M first having
a 01 separator before the message K, and also that P will have 00 prepended to
it.


### Probabilistic Signature Scheme (PSS)
Is similar to what OEAP provides for RSA encryption, PSS provides for RSA
Signatures. The goals is to make message signing more secure.

```
+---------+    +-------------------+    +---+    +-----------+    +---+
| Hash(M) |--->| Padding Algorithm |--->| P |--->| RSA(n, d) |--->| S |
+---------+    +-------------------+    +---+    +-----------+    +---+
```
So we take the message that we want to sign and create a hash of it as the first
step. This allows us to sign a message of any length as the hash will output
the same length message regardless. Using SHA-256 the length would be 256 bits.

Like OAEP PSS also requires a PRNG and two hash functions. 

### PKCS #1v 1.5 padding
This was used in TLS version prior to 1.2.



