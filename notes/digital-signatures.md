## Digital Signatures
These are more protocols that use previous symmetric (3DES, AES...) and
asymmetric (RSA, DH, ECC) algorithms

The goal is to provide authenticity meaning that we can verify that a message
is coming from the entity that sent it. Like a signature on in normal letter or
document. 
```
  +---------------+
  |Dear,          |
  |               |
  |               |
  |               |
  |_______________|
  |Signature:     |
  |Daniel Bevenius|
  +---------------+
```

### Overview
A digital signature is the equivalient to such a signature, but what
we want to sign is a digital document. 

```
  +--------------+
  |001010101000000|
  |101010101000100|
  |001010000000001| ------x-------+
  |001011111110001|               |
  |001011111110000|               | 
  |001011111110001|           sig(x, k)      k = key
  |_______________|               |
  |Signature:     |               |
  |001011111110001|               |
  |101011111110001|<------y-------+
  |021011111110001|  
  |001000000010010|  
  +---------------+
```
Now, the above is done on the signer side and the document, `x`, and the
generated signature `y` is sent over a channel to the reciever:
```
Sender ----> (x, y) ------> Receiver
```
Now for a normal signature someone would check, visually look at the signature
to verify it and if it looks correct it would be taken as authentic. But for
a digital signature which is just a number of bits that does not work.
```
Sender ----> (x, y) ------> Receiver        true, if y is valid
                            ver(x, y, k) = {false, if y is invalid 
```
The key could be exchanged using Diffie-Hellman as an example.


### Security Services
"The objectives of a security system are called security services".

#### Confidentiality
Prevent others from reading, the message is kept secret and only authorized
parties can read. 
```
Encrypt -----------------> Decrypt
```
Bad guy: Third party

#### Message Authentication
The sender of the message is authentic, which is what this document is all
about, digital signatures.

Bad guy: Third party

#### Message Integrity
That the message has not been modified. Take the example above where we have
the plaintext document as input to the signature function along with the key.
This means that if the plaintext x is modified in transit the signature y would
be different (hopefully) so this means that the verification function would
fail if it is manipulated.
So digital signatures provides authenticity and integrity.

Bad guy: Third party

#### Nonrepudiation
The sender of a message cannot deny the creation of the message.

In our example above we don't have this. The sender can say that she never
sent the message to the reciever. The only thing the reiever has is the key
which they claim proves that Alice sent it, but they could have generated
the key and the document x, and then signed it them selves and then claim that
Alice sent it. But more probably the issue would be that Alice regrets
a purchase or something like that and claims she never sent it.

Bad guy: Sender/Reciever

When we use symmetric keys both parties can do the same things, but with
asymmetric keys we can achive nonrepudiation and was one of the main motivations
for asymmetric keys cryptography.

Asymmetric keys:
```
  +--------------+
  |001010101000000|
  |101010101000100|
  |001010000000001| ------x-------+
  |001011111110001|               |
  |001011111110000|               | 
  |001011111110001|           sig(x, pri_k)      k = private key
  |_______________|               |
  |Signature:     |               |
  |001011111110001|               |
  |101011111110001|<------y-------+
  |021011111110001|  
  |001000000010010|  
  +---------------+

Sender ----> (x, y) ------> Receiver            true, if y is valid
                            ver(x, y, pub_k) = {false, if y is invalid 
```
In this case Alice uses here private key to generate the signature and the
receiver can use here public key to verify the signature. Only Alice knows the
private key so only Alice is capable of signing the document which is what we
want. And in this case the reciever cannot generate the signature them selves
either which was possible with symmetric keys.

Using symmetric keys are still useful and do provide message integrity and is
used for message authentication codes (MAC).

### RSA Digital Signatures
```
Alice                                        Bob
                         
KprA, KpubA       -----KpubA----------->  
s = sig(x, KprA)  -----(x, s)----------> ver(x, s, KpubA) = {true, false}

```
We have the setup phase where we need to compute the key-pair.
```
KprA  = (d)
KpubA = (n, e) 

                  -----(n, e)---------->  

s = sig(x, KpriA) ≡ x^d mod n
(notice that we are using the private key d, as opposed to RSA public key
cryptography where we would have used e).

                  -----(x, s)---------->  ver(x, s, (n, e)):
                                          s^e ≡ x' mod n      // uses the public exponent e
  
                                          x' { == x => valid
                                               != x => invalid
                                          
```
Proof of correctness:
```
s^e = (x^d)^e = x^de ≡ x mod n
```

Signing:
```
x^d mod n
```
This is a costly operation to perform and square-and-multiply algoritm is used.
(x^d mod n)

Rule of thump; about 1000 times slower than AES.

Verification:
Also needs to compute a costly square-and-multiply operation:
```
s^e mod n
```
In practice the value of e is often:
```
e = 3
e = 2¹⁶-1
```
And this make verification very fast.


### Existential forgery attack against RSA DS
```
Alice              Eve                       Bob
                         
                                             Kpub=(n, e), Kpr=d
                  <----(n, e)-----------     s = sig(x, Kpr)

                  <----(x, s)-----------
Verification:
s^e ≡ x' mod n
x == x'
```
In this case Eve would like to generate a message with a signature that is
a valid signature from Bob. That way she would be able to forge a message
which looks like comes from Bob. The example given is that if Alice is a bank
then Eve could generate a message that transfers money from Bob's account into
Eve's account and if Eve can generate a valid signature of Bob's then the bank
would allow the transfer.

Eve:
```
1) Chooses a number s ∈ Zn
2) x ≡ s^e mod n  <--------------------------------------------------------------+
3) Sends x to Alice (personating Bob) ------(x, s)----> Alice                    |
                                                        x' ≡ s^e mod n           |
                                                        x == x'                  |
                                                        s^e mod n == s^e mod n <-+

```
So Alice verifies the signature to be correct. But it is not a simple task for
Eve to choose the signture s such that s^e mod n = x. She has to generate an x
which does what she wants (transfer the money) but she has to do that by guessing
values of s and then performing s^e mod n. Remember that Eve does not control
e which is the public exponent. So is this only a theoretical attack were Eve
could get Alice to verify a message but not really get Alice to do anything
real with it. But sending this might allow Eve to get past a layer in Alice's
application as the message would pass the verification and proceed.

What we have been discussing so far is called "school book RSA" and is the basic
way RSA works. But in real world senarious we need more to avoid attacks like
this.
In pratice we impose formatting rules on x which can be checked by Alice. With
the school book examples there were no resitricitons on x, it would be any
value.

Formatting example:
```
    <-----------1024 bits-------------->
x   +-----------------------+----------+
    |         m             |1111111111|
    +-----------------------+----------+
    <-------900 bits-------><--124----->
                             Padding
```
So in this case Eve will need to produce a message x which has 124 1s. To get
a one in the first position that is a 50/50 chance so it could take two tries 
to get a 1 in the first position. To get two ones that would require 4 tries, 
and to get three ones would require 8 tries (2³). Remember this is on average,
you might get lucky, but on average it would require 2¹²⁴ tries to get the
padding right which is a huge number.

Eve has a chance of 2⁻¹²⁴ to generate a message x, with 124 trailing 1s.
```text
  1
----- = 2⁻¹²⁴ 
2⁻¹²⁴ 
```


### Elgamal Digital Signatures
Elgamal digital siguatures is a little different from Elgamal encryption.

```
Alice                                        Bob
                                 ⌈Choose large prime, primitive el α ⌉
                                 |gen random Kpr = d ∈ {2,3,...,p-2} | Keygen
                                 |(y ≡ α^Kpr mod p) (y=public key)   | phase
                                 ⌊β ≡ α^d mod p  (β=public key       ⌋
               Kpub (β, p, α)
            <------------------
                                 ⌈Empherial key K_e ∈ {2,3,...p-2}:gcd(K_e, p-1)=1⌉
                                 |r = α^K_e mod p                                 |
                                 ⌊s = (x-d*r)K_e⁻¹ mod p                          ⌋
                {signature}
                    ↓
               x (r, s)
            <------------------

Verify
t = β^r*r^s mod p
t = { ≡ a^x mod p => valid
     !≡ a^x mod p => invalid    
                                 
```

