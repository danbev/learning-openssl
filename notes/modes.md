# Modes of operation
The reason for using modes is that when we have block ciphers that operate on
using a specific block size. But unless the data we want to encrypt is exactly
that size we need to break it up into smaller chunks and encrypt each one. This
document contains notes on the various techniques that can be used for this.

```
              Modes of operation
                 /             \
                /               \
Deterministic  /                 \ Probabilistic
              /                   \
           +-----+      Block    /  \    Stream
           | ECB |      Ciphers /    \   Ciphers
           +-----+             /      \
                           +-----+   +-----+
                           | CBC |   | OBF |
                           +-----+   +-----+
                                     +-----+
                                     | CFB |
                                     +-----+
                                     +--------------+
                                     | Counter Mode |
                                     +--------------+
```

## Electronic Code Book (ECB)
This is the simplest mode where the input text/data is split into blocks equal
to the ciphers length, and then each block is encrypted separately. Blocks that
are smaller than the ciphers size can be padded.
```
Encryption

     M₁   M₂   M₃
     ↓    ↓    ↓
     E    E    E
     ↓    ↓    ↓
     C₁   C₂   C₃
```
Now if the input messages happen to be the same then the cipher text will be
identical. This is very performant as all blocks can be processed in parallel.

```
Decryption

     M₁   M₂   M₃
     ↑    ↑    ↑
     E    E    E
     ↑    ↑    ↑
     C₁   C₂   C₃
```


## Cipher Block Chaining (CBC)
```
Encryption
     M₁   M₂   M₃
     ↓    ↓    ↓
IV-->x +->x +->x                      X=xor
     ↓ |  ↓ |  ↓
     E |  E |  E
     | |  | |  |
     +-+  +-+  |
     ↓    ↓    ↓
     C₁   C₂   C₃
```
This fixes the problem with the same input not generating identical outputs.
Decryption works in the opposite order, so C₁ is passed through the decription
algorithm used and then xor:ed with the IV which was sent with the message.
The IV is used so that the if the same first block is passed into the cipher it
will not generate an identical output block.

One downside of CBC is that it is no longer possible to encrypt in parallel, 
since to encrypt message block 2 we first have to encrypt message block 1 and
so on.

```
Decryption

     M₁   M₂   M₃
     ↑    ↑    ↑
IV-->x +->x +->x                      X=xor
     ↑ |  ↑ |  ↑
     E |  E |  E
     | |  | |  |
     +-+  +-+  |
     ↑    ↑    ↑
     C₁   C₂   C₃
```
During decryption there is also an issue where it is possible for an attacker
to manipulate bits in cipher block 2 which would directly effect the decryption
of message block 3. Changing cipher block 2 will mess up the decryption of that
message, but there are attacks like padding attacks that are possible with this
mode of operation.

## Counter Mode (CTR)
Is also known as CM, Integer Counter Mode, and Segmented Counter Mode (SIC).

```
n = nounce (number unique to a specific communication)

Encryption

     n+1    n+2    n+3 
     ↓      ↓      ↓
     E      E      E
     ↓      ↓      ↓
     n₁     n₂     n₃                    nₓ = 128 random bits
     ↓      ↓      ↓                     X  = xor
 m₁->x  m₂->x  m₃->x
     ↓      ↓      ↓
     C₁     C₂     C₃
```
What we now have is that each message will produce a unique/different cipher
text and it is possible to "jump" a position in the chain and decrypt that as
there are no dependencies on earlier decryption. We just have to do
`nounce + n`.

```
Decryption

     n+1    n+2    n+3 
     ↓      ↓      ↓
     E      E      E
     ↓      ↓      ↓
     n₁     n₂     n₃                    nₓ = 128 random bits
     ↓      ↓      ↓
 m₁<-x  m₂<-x  m₃<-x
     ↑      ↑      ↑
     C₁     C₂     C₃
```
Both notice that an attacker could change the ciphertext which will effect
the message block (plain text). 

## Counter with CBC-MAC (CCM)
This type of encryption combines counter mode encryption with a message
authentication code (MAC). What it is trying to do is to address the issue
in CTR where an attacker could change a cipher text block which could directly
affect the decrypted message block. Here a MAC is computed on the ciphertext
and will only decrypt if the ciphertext has not been changed. Doing it this way
is called encrypt-then-mac. The encryption stage produces encrypted ciphertext
blocks and also a tag which is a mac for these cipher blocks.

```
      Key
       ↓
m ->  AES    --> Cipher Text   --> 
       ↑         MAC
       IV
```


### Galios Counter Mode
In the previous section we mentioned that an attacker could manipulate the
cipher text block which would impact the message block decrypted and there
would be no way for the receiver to know that that was not the correct
information.



## Cipher Feedback Mode (CFB)
