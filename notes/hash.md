### Hashing
Most hashing functions take a variable input and produce a fixed length output.
```
           +-----------------------------------+
           |          Message M                |   (any lenght)
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
	           |   Hash value    |              (fixed lengt)
                   +-----------------+
```

One usage of hashing is where we want to create a digital signature of a
message or a file (something larger than the size that our signature algorighm
key) it would have to be split into blocks and encrypted separately. If this
is a large file that would take some time, and the same thing would have to be
done on the receiving side. What can be done instead is pass the message/file
through the hash function and get back a fixed lenght output, which we can then
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
           |          Message M                |   (any lenght)
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

