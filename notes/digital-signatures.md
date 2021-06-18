## Digital Signatures
These are more protocols that use previous symmetric (3DES, AES...) and
assymmetric (RSA, DH, ECC) algorithms

The goal is to provide authenticity meaning that we can verify that a message
is coming from the entidy that sent it. Like a signature on in normal letter or
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
Now, the above is done on the signer side and this the document, `x`, and the
generated signature `y` is sent over the reciever:
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
which they say proves that at alice sent it, but they could have generated
the key and the document x and signed it them selves and then claim that
alice sent it. But more probably the the issue would be that Alice regrets
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
In this case Alice isues here private key to generate the signature and the
receiver can use here public key to verify the signature. Only alice knows the
private key so only alice is capable of signing the document which is what we
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
                                          s^e ≡ x' mod n
  
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
This is a costly operation to perform and square-and-calculate algoritm is used.

Verificaion:
```
s^e mod n
```
In practice the value of e is often:
```
e = 3
e = 2¹⁶-1
```
And this make verification very fast.
