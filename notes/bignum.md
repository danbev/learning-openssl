## BIGNUM (BN)
Bit-Integer arithemtic involve numbers that don't fit into single 32/64-bit
registers. Instead the digits need to be stored in memory. These digits are
stored in an array, divided into chunks.

Is needed for cryptographic functions that require arithmetic on large numbers
without loss of precision. A BN can hold an arbitary sized integer and
implements all operators.

Usage:
```c
    BIGNUM* three = BN_new();
    BN_set_word(three, 3);
    BN_free(three);
```

`crypto/bn/bn_local.h`
```c
struct bignum_st {                                                              
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit        
                                 * chunks. */                                   
    int top;                    /* Index of last used d +1. */                  
    /* The next are internal book keeping for bn_expand. */                     
    int dmax;                   /* Size of the d array. */                      
    int neg;                    /* one if the number is negative */             
    int flags;                                                                  
}; 
```

64 bit-processors:
```c
#  define BN_ULONG        unsigned long
#  define BN_BYTES        8 
```

32 bit-processors:
```c
#  define BN_ULONG        unsigned int
#  define BN_BYTES        4 
```

So `d`, the digits will be a pointer to an unsigned long or int depending on the
processor used, and it will be divided into chunks the size of BN_BITS2:
```c
# define BN_BITS2       (BN_BYTES * 8)                                             
# define BN_BITS        (BN_BITS2 * 2)
```
So for a 64-bit processor we would have something like:
```
        8        8       8        8        8        8
    +----------------------------------------------------+
    |        |       |        |        |        |        |
    +----------------------------------------------------+
    ↑                                                ↑ 
    d                                               dmax
```
A newly initialized BIGNUM would have the following values:
```console
(BIGNUM) $0 = {
  d = 0x0000000000000000
  top = 0
  dmax = 0
  neg = 0
  flags = 1
}
```
If we try setting word as shown above the digits array must first be set or
expanded. Depending on the value being being set will determine the max number
of elements in the digits array (dmax). In the case of `3` this would only
need one chunk/slot. The slot(s) are then populated in BN_set_word
```console
(lldb) expr a->d[0]
(unsigned long) $7 = 3

(lldb) expr *a
(BIGNUM) $9 = {
  d = 0x00000000004056d0
  top = 1
  dmax = 1
  neg = 0
  flags = 1
}
```
Now, lets take a look at a more complicated bitnum.
```console
(lldb) expr *pub_key
(BIGNUM) $15 = {
  d = 0x0000000005b15580
  top = 24
  dmax = 24
  neg = 0
  flags = 1
}
```
So we can see that the array will have 24 chunks of data in it. And remember
that d is just a pointer to the first entry.

I was wondering how a comparison is done with BIGNUMs 
