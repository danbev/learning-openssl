## Elgamal encryption scheme
Diffie-Hellman uses the descrete logarithm problem (DLP) to establish a key
exchange. This section looks at an encryption scheme that used DLP.

For some background here we are talking about public-key algorithms and they
can be used for multiple things:
```
                                                   Descrete Logarithm
	                Integer factorization  |    Zp^*        EC 
-----------------------------------------------------------------------
 Key exchange         | RSA                    |    DH        |  ECDH
 Digital signatures   | RSA                    |  Elgamal+DSA |  ECDSA
 Encryption           | RSA                    |  Elgamal     |  EC-Elgamal
```


First lets recall the Diffie-Hellman key exchange using Zp^*:
```                                                                             
Alice                   Public domain parameters       Bob
------------------------------------------------------------------------
                        α (generator/primitive element)
                        p (prime number)

a = KprA ∈ {2,..., p-2}                                b = KprB ∈ {2,..., p-2}
A = KpubA = α^a mod p   <----------------------->      B = KpubB = α^b mod p


K_ab = (B)^a mod p                                     K_ab = (A)^b mod p
```
Now the session keys calculated could be used as the key for a symmetric
encryption algorithm. But in the case of Elgamal we want to use this to encrypt
directly. This is done by multiplying the message with the secret key:
```
message * K_ab mod p = y     --------------------------> y * K_ab^-1 mod p
                                                         y / K_ab    mod p
```
This is basically what Elgamal does, but it changes some of the earlier parts
of the scheme for efficiency reasons (I think).

So Elgamal is a variant of DH is not very difficult to understand it is pretty
much as explained above but in pratice the implementation differs from this
simplistic view. It reorders steps in DH.

Elgamal was invented around 1985 and Taher Elgamal was the inventor. 


```                                                                             
Alice                                                  Bob
------------------------------------------------------------------------
                                                       α (generator/primitive element)
                                                       p (prime number)
                                                       
                        (β, p, α)                      Kpr = d ∈ {2,..., p-2}
                    <---------------------------       Kpub = β = α^d mod p
i ∈ {2,..., p-2}
K_e = α^i mod p ("Ephemeral"/"temporary or short lived" key)
      (same as Alices public key in normal DH)

K_m = β^i mod p  ("Masking" key)
      (same as the session key in normal DH)

y = x * K_m mod p  (x = message)
                        (y, K_e) 
                    ------------------------------>    
                                                        K_m = K_e^d mod p
                                                        x = y K_m^-1 mod p
                                                        x = y / K_m  mod p

```

Recall:
```
 α^x = A mod p

x = Kpr  (private key)
A = Kpub (public key)
α = generator/primitive element
```

Notice that Bob now has the domain parameters which he choses and they are not
in the public domain like in DH.

```
y * K_m^-1 =  y        * (K_e^d)^-1 mod p
y * K_m^-1 = (x*K_m)   * K_e^-d     mod p
y * K_m^-1 = x*β^i     * (α^i)^-d)  mod p
y * K_m^-1 = x(α^d)^i  * (α^i)^-d)  mod p
y * K_m^-1 = xα^id     * α^-id      mod p
y * K_m^-1 = xα^(id-id)             mod p
y * K_m^-1 = xα^(0)                 mod p
y * K_m^-1 = x * 1                  mod p
```

Now if you are only going to encrypt once then there are the same number of
steps in both DH and Elgamal. But if Bob wants to communicate with multiple
people and encrypt then the same public key is used.
The public key K_e must be different for every plaintext that is to be
encrypted. So we have to use the generator to get a new value for `i` each
time we want to encrypt otherwise if we reuse the same value that will result
in the same ciphertext. The masking key need to change otherwise we are just
multiplying the same values to produce y.
