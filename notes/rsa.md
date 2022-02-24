### Rivest Shamir and Aldeman (RSA)
Is actually two algoritms, one for asymmetric key encryption (key exchange) and
one for digital signatures (like signing public-key certificates).

Is a public key encryption technique developed in 1978 by the people mentioned
in the title. It is an asymmetric system that uses a private and a public key.
RSA is somewhat slow and it not used to encrypt data in a communication, but
instead it is used to encrypt a symmetric key which is then used to encrypt data.

It starts by selecting two prime numbers `p` and `q` and taking the product of
them:
```
N = pq

p = 2, q = 7
N = 2*7 = 14
```
`N` will become our modulus.

What are the values that don't have common factors with our modulus (14)?
```
1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
1, x, 3, x, 5, x, x, x, 9,  x, 11,  x, 13,  x
1, 3, 5, 9, 11, 13
```
So we have 6 values that don't have common factors with 14.

This can also be calculated using:
```
L = (q - 1) * (p - 1)
L = (2 - 1) * (7 - 1)
L = (1) * (6) = 6
```
So `L` will be `6`.

For encryption we will have a key that consists of a tuple, where one value
will be the modulus we calculated above:
```
(?, 14)
```
The encryption key must be a value between 1 and the value of 'L', which in our
case gives us 4 values to choose from, `2, 3, 4, 5`.
The value we choose must not share any other factors besides 1 with L(6), and
our modulus(14). `5` is the only option in our case:
```
(5, 14)
```
This is the public key exponent which we will see later is used as the exponent
that we raise the value to be encrypted (m) to:
```
m⁵ mod(14) = encrypted value
```

Decryption also uses a tuple with one being the modules as well:
```
(?, 14)
```
To calculate the private key value we use the following formula:
```
D * E % L = 1
```
And with concrete values:
```
D * 5 % 6 = 1
```
Options for D:
```
5, 11, 17, 23, 29, 35, ...
```
Let choose `11`:
```
11 * 5 % 6 = 1
55 % 6 = 1
```
This values is called the private exponent because in much the same way as
the public exponent the encrypted value(e) will be raised to this value:
```
y^d mod n = (x^e)^d mod n = x^ed mod n = x
```
Where y is the encrypted value, which is the same as the plain text x raised
to the encryption exponent e mod n. So we can write the decryption as the
plain text raised to encryption exponent times the decryption exponent mod n.

```
e¹¹ mod(14) = decrypted value
```

Encryption and decryption:
```
message = 2
m⁵ mod(14) = encrypted value
2⁵ mod(14) = 4

encrypted value = 4
4¹¹ mod(14) = 2
```
And notice that 4 in our case is m⁵, which is 2⁵ mod 14 so we can write this as:
```
(m⁵)¹¹ mod (14)
m⁵*¹¹ mod (14)
m⁵*¹¹ mod (14) = m⁵⁵ mod (14) =
```

Now, there are issues with the what we have done above, first encrypting the
same plaintext multiple times will produce the same cipher text. There is also
an issue where if we multiply two identical ciphertexts with each other mod n we
will get the plain text.
```
y1 × y2 mod n = x1^e × x2^e mod n = (x1 × x2)^e mod n
```

To avoid this we use padding.
Optimal Asymmetric Encryption Padding (OAEP or sometimes RSA-OAEP).

In this case we create a bit string as large as the modulus, so a bit string
of size 14 in our current example. This is padded before encrypion. The bits
need to be random or otherwise they would just be the same problem as before,
so OAEP needs some form of pseudorandom number generator.

I've see the following in books/blogs etc describing padding:
```
M = H || 00 . . . 00 || 01 || K
```
And I was not sure what `||` meant, but looking at the notation section in
https://tools.ietf.org/html/rfc3447#section-2 I see it means it's a
concatenation operator. This section is also useful if you come accross variable
names that might not be obvious at first in OpenSSL.
Notice the 01 which is used as a separator above that is appended above which
is why we have to subtract two from M. TODO: explain and verify this.

Length of an octet is 8 so we are talking about byte length.

### RSA-PSS
Is one of the signature schemes in RSA. PSS stands for Probabilistic Signture
Scheme. PSS requires parameters like the hash function to be used and the mask
generation function (MGF). PSS is randomized and will create a different
signature each time. Is a signature scheme with appendix which means that it
does not sign the message itself but instead signs a hash of the message. This
hash is produced by the hash/algorithm/message digest function.

### RSA small messages
If the messages being sent are smaller than the modulus the modulus operation
can be avoided as it does not do anything. For example:
```
2^1 mod 4 = 2
```
We need to have a message that is greater than the modulus size. This is where
various padding schemes come into play with RSA.

### PKCSv1 (Public-Key Cryptography Standard version 1)
A part of this standard includes RSA encryption, decryption, encoding/padding
schemes. The padding scheme can be used with RSA to avoid the small messages
problem discussed above.
For example, say we have an AES 128 bit key that we want to encrypt and send to
a receiver. This will need to be expanded to 2048 bits and this is done using
padding. For example;
```
                           2048 bits
      +----+------+------+------------------------+
      |Op  |Random| 0xFF | msg                    |
      +-----------+------+------------------------+
Bits:  16    r       16     128

Op = Operation, 0001 is for signatures, and 0002 is for public key encryption
Random = random number but must not contain any 0xFF.
```
The idea here is that this is what is passed into the RSA encryption function
and sent to the other side.
The receiver will decrypt the ciphertext and check the first bits 0x0002 to
make sure that it has the correct padding format, and if it does not an error
might be returned. And here in lies the issue. This lets an attacker that can
intercept a ciphertext to modify the ciphertext and send it to the server, if
the server does returns an error the attacker has a way of finding out if the
changes pass encryption or not (if the server returns an error or not).


### RSA Optimal Asymmetric Encryption Padding
An improvement over PKCS#1 with regards to its padding scheme.
```
G: hash function that returns g bits
H: hash function that returns h bits
r: random nonce of g bits
```
