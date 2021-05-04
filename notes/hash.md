### Hashing
Most hashing functions take a variable input and produce a fixed length output.
```
           +-----------------------------------+
           |          Message M                |   (any length)
           +-----------------------------------+
                            |
                            ↓
           +-----------------------------------+
           \                                   /
            \     Hash function H(M)          /
             \                               /
              -------------------------------
                            |
                            ↓
                   +-----------------+
	           |   Hash value    |              (fixed length)
                   +-----------------+
```

One usage of hashing is where we want to create a digital signature of a
message or a file (something larger than the size than our signature algorighm
key) it would have to be split into blocks and encrypted separately. If this
is a large file that would take some time, and the same thing would have to be
done on the receiving side. What can be done instead is pass the message/file
through the hash function and get back a fixed length output, which we can then
sign using our signature algorighm. The signature is also sent with the message
and if we did not sign just the hash but the entire message we would double the
size of the data to be sent, perhaps over a network.


### RSA digital signature
```

Alice                            Bob
               <----  Kpub -----      Z = h(x)
               <---- (x, s) ----      s = sig_kpr(Z)

Z = h(x)
sig_kpub(Z) = true/false
```

### SHA-1

```
           +-----------------------------------+
           |          Message M                |   (any length)
           +-----------------------------------+
                            |
                            ↓
           +-----------------------------------+
           \                                   /
            \            SHA-1(M)             /
             \                               /
              -------------------------------
                            |
                            ↓
                   +-----------------+
	           |   Hash value    |              160 bits
                   +-----------------+
```
SHA-1 uses a Merkle-Damngård construction:
```
x = (x₁....xn)
     ↓
 +--------------+
 | padding      | Output size if 512 bits
 +--------------+
     ↓    ↓-----------+
 +--------------+     |
 \ compression /      | This value is fed back into the compression function
  +-----------+       | with the xi. The size of this value is 160 bits
     ↓                |
     +----------------+
     | When xn inputs have been processed we continue
     ↓
   H(x)  the hash function. x is 160 bits

```
the padding and compression is the Merkle-Damgard construction.

Lets take a closer look at the compression function:
Compression:
```
      x_i (512 bits)          H_i-1 (160 bits)
        |                       |
        ↓                       ↓----------+
+----------------+  W₀     +----------+    |
| Msg scheduler  | ------> | Round 0  |    |
+----------------+  32 bit +----------+    |           80 rounds
        |                       ↓          |
        |           W₁     +----------+    |
        +----------------> | Round 1  |    ↓
        |           32 bit +----------+    |
        ...                    ...         |
        |                       ↓          |
        |           W₈₀    +----------+    |
        +----------------> | Round 79 |    |
                    32 bit +----------+    |
                                | 32       |
                               [+]<--------+  add modulo 2³²
                                |   32
                                ↓
```
`w` are sub messages of size 

H_i-1 which is 160 bits is divided into four groups of 40 bits each
```
   +------------------------------------+
   |                160                 |
   +------------------------------------+
     ↓       ↓       ↓        ↓      ↓
   +----+  +----+  +----+  +----+  +----+
   | A  |  | B  |  | C  |  | D  |  | E  |
   +----+  +----+  +----+  +----+  +----+
     32      32      32      32      32
   
```
These 32 bit (words) are called the state. Notice that for the first round there
nothing, that is H₀ so the initial state is provided as:
```
S[0] = 0x67452301;
S[1] = 0xefcdab89;
S[2] = 0x98badcfe;
S[3] = 0x10325476;
S[4] = 0xc3d2e1f0;
```

Rounds:
4x20 = 80 rounds
There are 4 stages:
```
stage t=1, round j=0...19
stage t=2, round j=20...39
stage t=3, round j=40...59
stage t=4, round j=60...79
```

Each round has 5x32 (160) bits inputs (A, B, C, D, E) plus the message
schedule word W_j, which is also 32 bits.
```
         A    B    C    D    E
        (32) (32) (32) (32) (32)
         ↓    ↓    ↓    ↓    ↓
       +--------------------------+
w_j -> |        Round j           |
(32)   +--------------------------+


       +--------------------------+
       |  A  |  B  | C  | D  | E  |
       +--------------------------+
          |     |    |    |    |
          |     ↓    ↓    ↓    |
          |    +-----------+   ↓
          |    | f(B, C, D)|->[+]
       +-----+ +-----------+   ↓
       |<<< 5|--------------->[+] 
       +-----+  |    |    |    ↓
          |     |    |    |   [+]<---- Wj message scheduler value (32 bits)
          |  +-----+ |    |    |
          |  |<<<30| |    |    |
          |  +-----+ |    |    |
          |     |    |    |    |
          |     +-+  |    |    |
          |       |  |    |    |
          +-----+ |  |    |    ↓
                | |  |    |   [+]<---- kt round constant
          +-----|--------------+
          |     | |  |    |
          |     | |  |    +----+
          |     | |  +----+    |
          |     | +--+    |    |
          ↓     ↓    ↓    ↓    ↓
       +--------------------------+
       |  A  |  B  | C  | D  | E  |
       +--------------------------+


```
The 4 round functions are:
```
f0(B, C, D) = (B & C) | (!B & D) 
f1(B, C, D) = B ^ C ^ D
f2(B, C, D) = (B & C) | (B & D) | (C & D)
f3(B, C, D) = B ^ C ^ D
```
And the 4 round constats are:
```
c0 = 5A827999
c1 = 6ED9EBA1
c2 = 8F1BBCDC
c3 = CA62C1D6
```
And finally we have the message scheduler values:
```
```


This can be compared to block ciphers and how they work:
```
        K                      m
+----------------+  k₀     +----------+
| Key scheduler  | ------> | Round 0  | 
+----------------+         +----------+
        |                       ↓ 
        |           k₁     +----------+
        +----------------> | Round 1  |
        |                  +----------+
       ...                     ...
        |                       ↓ 
        |           ks-1   +----------+
        +----------------> | Round s-1|
                           +----------+
  
```

### SHA-3
November 2007 NIST issues a call for algorithms.
October 2008 deadline and they recieved 64 submissions.
December 2010 5 algorithms were left in the competition.
October 2012 Keccak was selected as SHA-3.

```
           +-----------------------------------+
           |          Message M                |   (any lenght)
           +-----------------------------------+
                            |
                            ↓
           +-----------------------------------+
           \                                   /
            \     SHA-3 Hash function H(M)    /
             \                               /
              -------------------------------
                            |
                            ↓
                   +-----------------+
	           |   Hash value    |              fixed lengts:
                   +-----------------+               224/256/384/512
```
Notice the fixed lengths (4) of them. 
```
224          2¹¹²     3DES key length
256          2¹²⁸     AES key length
384          2¹⁹²     AES key length
512          2²⁵⁶     AES key length
```
Recall that 2¹¹² are the steps an attacker needs to produce to create a
collision.

#### Kerrak
Can be used for other things and not just sha3.

Sponge construction:
1. Absorbing phase, input (like when you release a sponge it will such up fluid)
   x₁ is read and processed.
2. Squeezing phase, ouput (like when you squeeze the spong fluid will go out)

Parameters:
state which is like the internal bus length of Kerrac which can be configured
with a length (l) of `b = 25 * 2&l, where l={0,1,2,3,4,5,6}` which gives
`b ∈ { 25, 50, 100, 200, 400, 800, 1600 }`.
For SHA3 `l` must be 6 so b will be 1600.

rounds: n_r = 12 + 2l, which for SHA-3 becomes n_r = 12 + 2*6 = 24

output lengths:
```
output length      bus width     block size (r)  capacity (c)
224                1600          1152            1600-1152=448 
256                1600          1080            1600-1080=512
384                1600          832             1600-832=768
512                1600          576             1600-576=1024
224          

