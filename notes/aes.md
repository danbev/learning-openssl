## Advanced Encryption Standard
Symmetric key algorithm where the same key is used for encryption and
decryption.

```
  128 +---------+
x --->|   AES   |-----> y
      +---------+
           ↑
           | 128/192/256
           k
```
Notice the block size is always 128-bits (16 bytes) regardless of the keysize.

The number of rounds depends on the key length 128/192/256:
```
Key length |  Rounds
-----------|--------
128        | 10
192        | 12
256        | 14
```

NSA allows AES for classified data up to TOP SECRET with 192 or 256 bit keys.

As opposed to DES it is not a Fiestel cipher. AES encrypts the whole 128 bits in
each round which is different from what a Fiestel network cipher does.
TODO: include an example of the below in terms of an input message and a
key using ascii characters.

```
   127                               0
   +---------------------------------+       +-----------------+
   |                                 |       |    Key k        |
   +---------------------------------+       +-----------------+
                  ↓                                   ↓
   +---------------------------------+  k₀    +------------------+
   | KeyAddition                     |←-------| Transform 1      |
   +---------------------------------+        +------------------+
Round 0           ↓                                   ↓
   +---------------------------------+                |               Confusion
   | Byte substitution               |                |
   +---------------------------------+                |
                  ↓                                   |
   +---------------------------------+                |               Diffusion
   | ShiftRow                        |                |
   +---------------------------------+                |
                  ↓                                   |
   +---------------------------------+                |               Diffusion
   | MixColumn                       |                |
   +---------------------------------+                |
                  ↓                                   ↓
   +---------------------------------+  k₁    +------------------+
   | KeyAddition                     |←-------| Transform 1      |
   +---------------------------------+        +------------------+
                  ↓
.
.
.
.
Round 9           ↓                                   |
   +---------------------------------+                |
   | Byte substitution               |                |
   +---------------------------------+                |
                                                      |
   +---------------------------------+                |
   | ShiftRow                        |                |
   +---------------------------------+                |
                                                      ↓
   +---------------------------------+         +-----------------+  Key widening
   | KeyAddition                     |<--------| Transform  9    |
   +---------------------------------+         +-----------------+

```
Notice that each round has four layers (except for the last round which does
not have the MixColumn layer) and for 128-bits we have 10 rounds.

Remember that confusion is about making the relationship between the key and
the ciphertext as complex and involved as possible.

Diffusion refers to how each bit in the plaintext influences many of the bits
in the ciphertext.

AES is byte oriented so all operations are done on bytes and not individual
bits as was done in DES.

### Byte Substitution

```
  15  14  13  12    11  10   9   8     7   6   5   4     3   2   1   0   16 bytes (16*8=128)
 +---------------+ +---------------+ +---------------+ +---------------+
 |B₀ |B₁ |B₂ |B₃ | |B₄ |B₅ |B₆ |B₇ | |B₈ |B₉ |B₁₀|B₁₁| |B₁₂|B₁₃|B₁₄|B₁₅|
 +---------------+ +---------------+ +---------------+ +---------------+
  ↓   ↓   ↓   ↓     ↓   ↓   ↓   ↓      ↓   ↓   ↓   ↓    ↓   ↓   ↓   ↓ 
 +-+ +-+ +-+ +-+   +-+ +-+ +-+ +-+    +-+ +-+ +-+ +-+  +-+ +-+ +-+ +-+
 |S| |S| |S| |S|   |S| |S| |S| |S|    |S| |S| |S| |S|  |S| |S| |S| |S|
 +-+ +-+ +-+ +-+   +-+ +-+ +-+ +-+    +-+ +-+ +-+ --+  +-+ +-+ +-+ +-+
  ↓   ↓   ↓   ↓     ↓   ↓   ↓   ↓      ↓   ↓   ↓   ↓    ↓   ↓   ↓   ↓ 
 +---------------+ +---------------+ +---------------+ +---------------+
 |B₀ |B₁ |B₂ |B₃ | |B₄ |B₅ |B₆ |B₇ | |B₈ |B₉ |B₁₀|B₁₁| |B₁₂|B₁₃|B₁₄|B₁₅|
 +---------------+ +---------------+ +---------------+ +---------------+

       ↓             ↓             ↓             ↓
 +-----------+ +-----------+ +-----------+ +-----------+
 |    Sub    | |    Sub    | |   Sub     | |   Sub     |
 +-----------+ +-----------+ +-----------+ +-----------+
       ↓             ↓             ↓             ↓
 +---------------+ +---------------+ +---------------+ +---------------+
 |B₀ |B₁ |B₂ |B₃ | |B₄ |B₅ |B₆ |B₇ | |B₈ |B₉ |B₁₀|B₁₁| |B₁₂|B₁₃|B₁₄|B₁₅|
 +---------------+ +---------------+ +---------------+ +---------------+

```

### Substitutions S-boxes
Notice that there are 16 s-boxes and differenct from DES they are all the same.
The input to each s-box is 1 byte (8 bits) and the s-box will 
```
Ai   +---------------+ B'i   +---------------+  Bi   
---> |GF(2⁸) inverse | ----> |affine mapping | ----> 
     +---------------+       +---------------+
```
```
S(Ai) = Bi

A=C2
Which we split in two so that we can look the value up in the lookup table.
So x =12 and y=2  = 1100 0010  <- input to lookup
Bi = S(Ai) = 25₁₆ = 0010 0101  <- output from lookup
```
Notice that the values are hex and we have two of them to the lookup table will
have 16x16=256 entries.

In contrast to DES where the lookup tables were secret (how they were constructed
that is), I think they were generated randomly and the checked if known attacks
were possible, in AES they are not randomly generated and there is a mathematical
structure to it.

So we have Ai which are the following bits:
```
Ai = 1100 0010 
```
But this can also be viewed as a polynomial:
```
A=      1   1   0   0   0   0   1   0                  (bits)

Ai(x) = 1x⁷+1x⁶+0x⁵+0x⁴+0x³+0x²+1x¹+0x⁰                (polynomial)
      = x⁷+x⁶+³+1x¹
      = x⁷+x⁶+x
```
Now, we have to compute the inverse of this polynomial.
```
B'i(x) = x⁵+x³+x²+x+1 = A(x)^-1
        0010 1111

(x⁷+x⁶+x)(x⁵+x³+x²+x+1) = 1 mod x⁸+x⁴+x³+x+1
                               ↑
                           AES irreducalbe polynomial
```

