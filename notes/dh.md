### Diffie Hellman Key Exchange

```
Alice                 Public                        Bob
a (number < n)        g (generator, small prime)    b (number < n)
                      n (big prime number)

A = g^a mod n                                        B =  g^b mod n
                             A 
                     ----------------->
                             B
                     <-----------------

K_ab = (B)^a mod n                                   K_ab = (A)^b mod n


This is same as:                                     This is the same as:
(g^b)^a mod n  = g^ab mod p                          (g^a)^b mod n = g^ab mod p
```
Notice that they are both calculating the same value which is the secret key
that will be used for encryption. They have been able to communicate this in the
open and even if Eve gets a₁ or b₁ she does not have a or b, and to brute force
this would take a lot of time.

```
                           y            
y = AES(x)       --------------------->      AES⁻¹(y) = x
         K_ab                                       K_ab

```

Example:
```
a = 3                  g = 5                         b = 2
                       n = 7

                    a₁ = 5³ mod 7 = 125 mod 7 = 6
                    b₁ = 5² mod 7 = 25  mod 7 = 4

(b₁)³ = 4³ = 64 mod 7 = 1 (secret key)             (a₁)² = 6² = 36 mod n = 1
```
Notice that `g` for generator is like the starting point on the circle and n is
the max size of the circle after which is will wrap over.
  
```          
              n
            ______
           /      \
           |      | <-- g
           \______/

```
Visualize this as a circle (like a clock and 12 is the number n). So we take
our private key (a) and raise g to that, and then mod it to the circle, so this
will be a point some where on the circle. 

```          
a  = 3
a₁ = 5³ mod 7 = 125 mod 7 = 6

              n
              ↓
              7    1
 a₁--> 6    _____
           /      \  2
 g --> 5   |      | 
           \______/ 3
              4
```
Bob does the same and his value will also be somewhere on the circle. 
```          
b  = 3
b₁ = 5² mod 7 = 25  mod 7 = 4

              n
              ↓
              7    1
       6    _____
           /      \  2
 g --> 5   |      | 
           \______/ 3
              4
              ↑
              b₁
```

They can now share a₁ and b₁ publicly as just knowing the point on the cicle is
not enough, only alice knows how many times around the circle (a times) to get
to the point.

So after the exchange here is a secret key that both parties can use to encrypt
and decrypt messages and they would use a symmetric cipher like AES for this.

### MODP groups
These are predefined prime numbers based on digits of PI, and generator number.
So these are the values of `n` and `g`.

Remember that both parties must use the same prime (which they use mod p) and
the generator number, and these are simply precomputed values that both can use.
They can specify that these should be used.

As an example in Node.js a group name can be specified which will then be
used to looked up :
```c++
const node::Utf8Value group_name(env->isolate(), args[0]);                       
  const modp_group* group = FindDiffieHellmanGroup(*group_name);                   
  initialized = diffieHellman->Init(group->prime,                                  
                                    group->prime_size,                             
                                    group->gen);                                   
```

src/crypto/crypto_groups.h:
```c++
  typedef struct {                                                                   
    const char* name;                                                                
    const char* prime;                                                               
    unsigned int prime_size;                                                         
    unsigned int gen;                                                                
  } modp_group;                                                                      
                                                                                     
  static const modp_group modp_groups[] = {                                          
  #define V(var) reinterpret_cast<const char*>(var)                                  
    { "modp1", V(group_modp1), sizeof(group_modp1), two_generator },                 
    { "modp2", V(group_modp2), sizeof(group_modp2), two_generator },                 
    { "modp5", V(group_modp5), sizeof(group_modp5), two_generator },                 
    { "modp14", V(group_modp14), sizeof(group_modp14), two_generator },              
    { "modp15", V(group_modp15), sizeof(group_modp15), two_generator },              
    { "modp16", V(group_modp16), sizeof(group_modp16), two_generator },              
    { "modp17", V(group_modp17), sizeof(group_modp17), two_generator },              
    { "modp18", V(group_modp18), sizeof(group_modp18), two_generator }               
  #undef V                                                                           
  };

  static const unsigned char group_modp5[] = {                                    
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f,                   
    0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b,                   
    0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67,                   
    0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22,                   
    0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd, 0xef, 0x95,                   
    0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,                   
    0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51,                   
    0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,                   
    0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff,                   
    0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed, 0xee, 0x38, 0x6b, 0xfb,                   
    0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b,                   
    0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,                   
    0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda,                   
    0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8,                   
    0xfd, 0x24, 0xcf, 0x5f, 0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3,                   
    0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb,                   
    0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d, 0x67, 0x0c,                   
    0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,                   
    0xca, 0x23, 0x73, 0x27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,                   
    0xff, 0xff };
```
The FindDiffieHellmanGroup function simply iterates over all the names
and compares them to the passed in group name. Would it not be better to use a
map for this? TODO: take a closer look at this code.

Notice that the struct mod_p_group has a prime which is the character array
we see above which is the value of the prime to use (is part of the spec), and
it also as the size of the prime, and a generator value of 2.
```console
(lldb) expr group->prime_size
(const unsigned int) $16 = 192
```

modp1, modp2

modp5, modp15, modp16, modp17, modp18


### Safe prime
For a prime to be safe then for prime `p`, (p-1/2) must also be prime.
```
p = 11
(11-1)/2 = 5
```
So 11 would be a safe prime.

### OpenSSL implementation
We can find the Diffie-Hellman struct in `crypto/dh/dh_local.h`.
```c
struct dh_st {
    ...
    BIGNUM *pub_key;            /* g^x % p */                                      
    BIGNUM *priv_key;           /* x */  
    ...
}
```
`openssl/crypto/dh/dh_key.c`

