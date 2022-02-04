## Hash Message Authentication Code (HMAC)
What these are intended to do is to protect/guard agains ciphertext
manipulation. So just think about a message that gets encrypted into cipertext,
the only person that can decrypt is someone in possession of the private key
(assuming symmatric key encryption). But is it possible for someone to modify
the ciphertext. When the encryption algrorithm uses a block cipher this change
would affect the whole block but with a stream cipher it would only affect a
single byte. Anyway, this is what a HMAC is designed to protect, the receiver
can recalculate the tag generated before/after encryption to verify that the
plain-text/cipher-text has not been tampered with.

```
  +---------------------+------------------+
  |   message           | hash(message)    |
  +---------------------+------------------+

hash(message) = fixed length bits unique to the input message. And one way.
```
So in this case the receiver can verify the message was not tampered with. But
someone intercepting this message could update the message and then re-run the
hash function with that modified message and still the receiver would not know
that it had been tampered with.

We need to mix some encryption into this, like so: 
```
  +---------------------+------------------+
  |   message           | hash(k | message)|
  +---------------------+------------------+

k = symmetric key shared is appended to the message before hashing.
hash(message) = fixed length bits unique to the input message. And one way.
```
With this solution an attacker can intercept the message and change it, but
without the private key it will not be able to recompute the hash (remember that
the message the attacher intercepts is a hash of the key appended to the message
and they only see the output of the hash function which is a fixed lentgh string
of bits. But there are ways to workaround this depending on the hash function
used, like SHA1 or SHA256. 

```
              key -> key₁
                  -> key₂

  hash₁ = hash(k₁ | message)
  hash₂ = hash(k₂ | hash₁)
  or
  hash = hash(k₂ | (hash(k₁ | message)))

  +---------------------+--------------------------------+
  |   message           | hash(k₂ | (hash(k₁ | message)))|
  +---------------------+--------------------------------+ 

```
