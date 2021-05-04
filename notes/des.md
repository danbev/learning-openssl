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

### Confusion
Remember that confusion is about making the relationship between the key and
the ciphertext as complex and involved as possible.

### Diffusion
Diffusion refers to how each bit in the plaintext influences many of the bits.

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
   63                                0     64                           0
   +---------------------------------+     +----------------------------+
   |           Plaintext             |     |          Key               |
   +---------------------------------+     +----------------------------+
                   ↓                                    ↓
   +---------------------------------+     +----------------------------+
   |   Initial Permuation IP(x)      |     |    Permuted Choice (PC-1)  |
   +---------------------------------+     +----------------------------+
                   ↓                                    |
   63            28 27               0                  | 56-bits (64-8)
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
   |S₁|  |S₂|  |S₃|  |S₄|  |S₅|  |S₆|  |S₇|  |S₈|  (S-boxes)
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

### Expansion
In this step we are going from 32 bits to 48. So we are increasing the size
making the array bigger. This is a step prior to the xor operation with the
subkey, which happens to be 48 bits. This step provides diffusion (making
changes in the plaintext influece many of the bits):
```
        32-bits
          ↓
+-----------------------------------------------------------------------------------------------+
| 1| 2| 3| 4| 5| 6| 7| 8| 9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|
+-----------------------------------------------------------------------------------------------+
 |  |  |  |   |                                                                               |
 |  |  |  |   |                                                                               |
 +--|--|--|---|-------------------------------------------------------------------------------|------------------------------------------------+
 |  |  |  |   +--+----+                                                                       |                                                |
 |  |  |  +--+---|--+ |                                                                       |                                                |
 |  |  +---+ |   |  | |                                                                       |                                                |
 |  +--+   | |   |  | |                                                                       |                                                |
 +--+  |   | |   |  | |                                                                       |                                                |
    |  |   | |   |  | |                                                                       |                                                |
 +--|--|---|-|---|--|-|-----------------------------------------------------------------------+                                                |
 ↓  ↓  ↓   ↓ ↓   ↓  ↓ ↓                                                                                                                        ↓
+-----------------------------------------------------------------------------------------------------------------------------------------------+
| 1| 2| 3| 4| 5| 6| 7| 8| 9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|34|36|37|38|39|40|41|42|43|44|45|46|47|48|
+-----------------------------------------------------------------------------------------------------------------------------------------------+

Mapping table
+-----------------+
|32  1  2  3  4  5|
| 4  5  6  7  8  9|
| 8  9 10 11 12 13|
|16 17 18 19 20 21|
|20 21 22 23 24 25|
|24 25 26 27 28 29|
|28 29 30 31 32  1|
+-----------------+
```
Notice that 16 or the 32 input bits are copied once and 16 are copied
into two locations in the output array, so we get 16+12x2=48.

### S-box
Before this stage in a round the expansion of the 32-bits into 48 bits has
already happend, and that output has been xor:ed with the subkey. The output
from that will be the input to the s-box. These are substitution/lookup tables
which is why the are called s-boxes. This is the step that provides confusion.
``` 
                                                 |
        +--------------------+-------------------+-------------------+-------------------+-------------------+-------------------+-------------------+
        ↓                    ↓                   ↓                   ↓                   ↓                   ↓                   ↓                   ↓
+-----------------+ +-----------------+ +-----------------+ +-----------------+ +-----------------+ +-----------------+ +-----------------+ +-----------------+
| 1| 2| 3| 4| 5| 6| | 7| 8| 9|10|11|12| |13|14|15|16|17|18| |19|20|21|22|23|24| |25|26|27|28|29|30| |31|32|33|34|34|36| |37|38|39|40|41|42| |43|44|45|46|47|48|
+-----------------+ +-----------------+ +-----------------+ +-----------------+ +-----------------+ +-----------------+ +-----------------+ ------------------+
        ↓                    ↓                   ↓                   ↓                   ↓                   ↓                   ↓                   ↓
  +-----------+         +----------+        +-----------+        +-----------+      +-----------+        +-----------+     +-----------+        +-----------+ 
S1| 1| 2| 3| 4|       S2|5| 6| 7| 8|      S3| 9|10|11|12|      S4|13|14|15|16|    S5|17|18|19|20|      S6|21|22|23|24|   S7|25|26|27|28|      S8|29|30|31|32|
  +-----------+         +----------+        +-----------+        +-----------+      +-----------+        +-----------+     +-----------+        +-----------+
        |                    |                   |                   |                   |                   |                   |                   |
        +--------------------+-------------------+-------------------+-------------------+-------------------+-------------------+-------------------+
                                                 ↓
                              +--------------------------------------------+
                              | Permutation                                |
                              +--------------------------------------------+
```
So for each s-box we have 6 input bits and we want to have a lookup table for
each of them. So each table will contain 2⁶ (64) entries.
```
000000   1110   14

111111   1101   13
```
There no underlying rule to the these lookup tables but instead the mapping
is provided by tables like the following:
```
+--------------------------------------------------+
|S₁| 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15|
---------------------------------------------------|
|0 |14 04 13 01 02 15 11 08 03 10 06 12 05 09 00 07|
|1 |00 15 07 04 14 02 13 01 10 06 12 11 09 05 03 08|
|2 |04 01 14 08 13 06 02 11 15 12 09 07 03 10 05 00|
|3 |15 12 08 02 04 09 01 07 05 11 03 14 10 00 06 13|
+--------------------------------------------------+
```
So find the row we use the first and last bit in the 6 bit input (together)
So for 000000 that would be 00 and then the 4 bits in middle to determine the
column, which is 0000 in this case so 0. 
```
110011
row: 11 = 3
col: 1001 = 9
So that should be output value 11 (1011)
```
Now we could just write this like I first did with 6 binary digits that map to
an number but apperently this way of using columns/rows is used in many books
and documentation so it might be good to understand it.

So how did IBM come up with these substitution/lookup tables?  
"Because it is secure, trust us" :) 
These values were chosen as they prevent diffential crypto analysis. This type
of attack was only discovered like 18 years after DES was invented. But IBM/NSA
must have know about these types of attacks but did not make that public and
perhaps they wanted to be able to use that attack against other crypto
algorithms. But it now seems like the attack was known by other parties that
were not relevling them either.

The last Permuation of the round is important as this will spread out the
bits affected by the previous xor and s-box (so that they are not local to
a section of the bit array). And this will mean that in the next round more
s-boxes will be involved and this continues allowing for even a single bit-flip
to affect many output bits.

### Key Schedule
If we look at the digrams above we a an input key which is then transformed
into 16 subkeys, one for every round.
The input key is 56-bits and each tras
```
        63                           0
        +----------------------------+
        |          Key               |
        +----------------------------+
                      ↓
        +----------------------------+
        |   Permuted Choice 1 (PC-1) |
        +----------------------------+
                     |
                     | 56-bits (64-8 parity bits)
                     |
          55         ↓            0
          +-----------------------+
          |   C₀     |   D₀       |
          +-----------------------+
     28-bits   ↓            ↓
          +----------+ +-----------+
          |   LRi    | |   LRi     |         Left Rotate 
          +----------+ +-----------+         1 position for rounds 1,2,9,16
               |            |                2 positions for rounds the rest
          55   ↓            ↓     0
          +-----------------------+
          |   Permuted Choice 2   |          8 bits are dropped and the rest
          +-----------------------+          permuted.
                     |
            48       ↓           0
            +--------------------+
            |   Sub key          |
            +--------------------+
         
```
In PC-1 the bits 8, 16, 24, 32, 40, 48, 56, and 64 are not used. So the last
it of each byte is removed. The rest of the bits are permuted.
Notice that in rounds 1, 2, 9, and 16 we shift by one bit position and the rest
of the 12 rounds we shift by 2, 2*12+4=28 in total. Notice that this will be
the same value as C₀ and likewise D₁₆ will be equal to D₀.

### Decryption
This deals with reversing the steps in encryption.

This first part below shows the last round of encryption:
```
   63            28 27               0
   +---------------------------------+
   |    L₁₅        |     R₁₅         |
   +---------------------------------+               +---------------+
         |       +------------|--------[ki]----------| Key scheduler |
  32-bits|       ↓ 48-bits    | 32-bits              +---------------+
         ↓    +-----+         |
        (+)←--|  f  |←--------+
         |    +-----+         |
         |                    |
         +----------------+   |
         +----------------|---+
         |                |
         ↓                ↓
   +---------------------------------+
   |    L₁₆        |      R₁₆        |
   +---------------------------------+
         |                 |                
         | +---------------+
         | |                
         +-|----------------+
           ↓                 ↓
   +---------------------------------+
   |    Final Permuation IP^-1(x)    |
   +---------------------------------+
                  ↓
   +---------------------------------+
   |    Initial Permuation IP1(x)    |
   +---------------------------------+
                  ↓
   63            28 27               0
   +---------------------------------+
   |    L₀         |     R₀          |
   +---------------------------------+                +----------------+
         |       +------------|--------[ki]-----------| Key schduler   |
  32-bits|       ↓ 48-bits    | 32-bits               +----------------+
         ↓    +-----+         |
        (+)←--|  f  |←--------+
         |    +-----+         |
         |                    |
         +----------------+   |
         +----------------|---+
         |                |
         ↓                ↓
   +---------------------------------+
   |    L₁         |      R₁         |
   +---------------------------------+
                  ...
```
So if we look at L₁₅ it will get encrypted and then it will be store in R₁₆,
and notice that they are crossed before the final permuation. So L₀ will be
the encrypted value of L₁₅ which will be decrypted and the output will be in
R₁. So R₁ = L₁₅, and L₁ = R₁₅ (which is not encrypted).

```
R₁ = L₀ ^ f(ki, R₀)
```
And we can write L₀ as:
```
L₀ = L₁₅ ^ k(k₁₆, R₁₅)
```
And if we replace L₀:
```
R₁ = L₁₅ ^ k(k₁₆i, R₁₅) ^ f(ki, R₀)
```
If we look at this part:
```
           k(k₁₆i, R₁₅) ^ f(ki, R₀)
```
If these two are the same values, xoring the same value will be 0 then the
only thing left in the expression is:
```
R₁ = L₁₅ ^ 0
```
And we know that R₀ is infact the same as R₁₅, and if we the provide the same
subkey this will indeed become 0:
```
R₁ = L₁₅ ^ k(k₁₆i, R₁₅) ^ f(k₁₆, R₁₅)
R₁ = L₁₅ ^ 0

 1110
^0000
-----
 1110
```


