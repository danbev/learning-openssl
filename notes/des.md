## Data Encryption Standard (DES)
Was purposed by IBM in 1974 with input from the NSA.

```
          x
          ↓ 64-bits
      +--------+
      |  DES   |←-- 56-bit key
      +--------+
          ↓
          y 64-bits
```
The same key is used for encryption and decryption (symmetric)
Inside DES there are 16 rounds of:
```
          x
          ↓ 64-bits
  +---------------------+
  | Initial Permuation  |
  +---------------------+
          ↓ 
  +---------------------+  k₁ 56 bits
  | Encryption Round 1  | ←----------+
  +---------------------+            |
          ↓                          |
         ...                         +---- K
          ↓                          |
  +---------------------+            |
  | Encryption Round 16 | ←----------+
  +---------------------+  k₁₆ 56 bits
          |
          ↓ 64-bits
  +---------------------+
  | Final  Permuation   |
  +---------------------+

```

Remember that confusion is about making the relationship between the key and
the ciphertext as complex and involved as possible.

Diffusion refers to how each bit in the plaintext influences many of the bits

Combining confusion/diffusion multiple times can build a strong block cipher:
(called a product cipher principal)
```
          x
          |
          ↓
  +----------------+
  | Confusion      |
  +----------------+
          ↓
  +----------------+
  | Diffusion      |
  +----------------+
          ↓
  +----------------+
  | Confusion      |
  +----------------+
          ↓
  +----------------+
  | Diffusion      |
  +----------------+
          ↓
         ...
          ↓
          y
```

Fiestel Network
Below we are showing the first round:
```
   63                                0     55                           0
   +---------------------------------+     +----------------------------+
   |           Plaintext             |     |          Key               |
   +---------------------------------+     +----------------------------+
                   ↓                                    ↓
   +---------------------------------+     +----------------------------+
   |   Initial Permuation IP(x)      |     |          PC-1              |
   +---------------------------------+     +----------------------------+
                   ↓                                    |
   63            28 27               0                  | 48-bits (56-8)
   +---------------------------------+                  |
   |    L₀         |     R₀          |      55          ↓              0
   +---------------------------------+      +---------------------------+
         |       +------------|--------[ki]-|     Transform 1           |
  32-bits|       ↓ 48-bits    | 32-bits     +---------------------------+
         ↓    +-----+         |                            |
        (+)←--|  f  |←--------+                            |
         |    +-----+         |                            |
         |                    |                            |
         +----------------+   |                            |
         +----------------|---+                            |
         |                |                                |
         ↓                ↓                                ↓
   +---------------------------------+         +---------------------------+
   |    L₁         |      R₁         |         |     Transform 16          |
   +---------------------------------+         +---------------------------+
         |                 |                
         | +---------------+
         | |                
         +-|----------------+
           ↓                 ↓
   +---------------------------------+
   |    Final Permuation IP^-1(x)    |
   +---------------------------------+
```
Notice that the bits 0-27 are simply copied over to the left and also fed into
f as a parameter in addtion to ki (the key bits provided by the key schedular).
Now, think about decryption and what would be needed to reverse this, we would
need the same key and also R₀, which in fact have as it is copied to L₁.

### Initial/Final Permutation (IP)
If we look above the input to the IP is 64-bits of plaintext which comes before
the rounds.
This is a simple bit permuation (like shifting, rotating etc)

Initial Permuation:
```
    1                       58      64           Mapping table
   +---------------------------------+     +-----------------------+
   | | | | | | | |....| | | | | | |  |   1→|58 50 42 34 26 18 10  2|
   +---------------------------------+     |60 52 44 36 28 20 12  4|
    |                        |             |62 54 46 38 30 22 14  6|
    |  +---------------------+             |64 56 48 40 32 24 16  8|
    +--|---------------+                   |47 49 41 33 25 17  9  1|←40
    +--+               |                   |59 51 43 35 27 19 11  3|
    ↓                  ↓                   |61 53 45 37 29 21 13  5|
   +---------------------------------+     |65 55 47 39 31 23 15  7|
   | | | | | | | |....| | | | | | |  |     +-----------------------+
   +---------------------------------+
    1                  40 

```
This copying in software and wiring in hardware so there is nothing strange
going.
Final Permuation:

```
   1                    40          64            Mapping table
   +---------------------------------+     +-----------------------+
   | | | | | | | |....| | | | | | |  |     |40  8 48 16 56 24 64 32|
   +---------------------------------+     |49  7 47 15 55 23 63 31|
    |                    |                 |38  6 46 14 54 22 62 30|
    |  +-----------------+                 |37  5 45 13 53 21 61 29|
    +--|---------------------+             |36  4 44 12 52 20 60 28|
    +--+                     |             |35  3 43 11 51 19 59 27|
    ↓                        ↓             |34  2 42 10 50 18 58 26|
   +---------------------------------+     |33  1 41  9 49 17 57 25|
   | | | | | | | |....| | | | | | |  |     +-----------------------+
   +---------------------------------+
                            58
```
There are tables that descibe how this copying/wiring is done. So the initial
permuations are undone by the final permuation. And the tables are public and
part of the standard so someone attacking this scheme could also do this.
If it does not add any security why is it part of the standard? I sounds like
it was for practical electrical engineering hardware reason for adding this,
remember that this was back in 1974.

### F function
```
   31              0
   +----------------
   |     Ri-1      |
   +---------------+
          ↓
   +-------------------+
   | Expansion E(Ri-1) |
   +-------------------+
          |
   48     ↓                  0
   +--------------------------
   |                         |
   +-------------------------+
          |
          ↓           48 bits
         (+)←------------------------ki
          |
    +-----+-----+-----+-----+-----+-----+-----+
    ↓     ↓     ↓     ↓     ↓     ↓     ↓     ↓  6 bits (48/8)
   +--+  +--+  +--+  +--+  +--+  +--+  +--+  +--+
   |S₁|  |S₂|  |S₃|  |S₄|  |S₅|  |S₆|  |S₇|  |S₈|
   +--+  +--+  +--+  +--+  +--+  +--+  +--+  +--+
    |     |     |      |    |      |     |    |  4 bits (4*8=32)
    +-----+-----+-----+-----+-----+-----+-----+
                         | 
                         |
                  31     ↓         0
                  +----------------
                  | Permuation P  |
                  +---------------+
                         |
                         ↓ 32 bits

```
