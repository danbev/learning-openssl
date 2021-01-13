### WebCrypto
https://www.w3.org/TR/WebCryptoAPI/
https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API

Is a JavaScript API for performing basic crypto operations like hashing,
signature generation and verification, encryption/decryption.
There are both cryptographic functions and key management functions.

TLS will help with encrypting data on the wire between a client and a server
but after that it can be stored decrypted on the server.

SubtleCrypto is the interface exposed and provides functions like:
```js
SubtleCrypto.encrypt()
SubtleCrypto.decrypt()
SubtleCrypto.sign()
SubtleCrypto.verify()
SubtleCrypto.digest()
SubtleCrypto.generateKey()
SubtleCrypto.deriveKey()
SubtleCrypto.deriveBits()
SubtleCrypto.importKey()
SubtleCrypto.exportKey()
SubtleCrypto.wrapKey()
SubtleCrypto.unwrapKey()
```

### CryptoKey
Represents a key in WebCrypto.
Has the following properties:

#### type
A String of one of the following values `secret`, `private`, `public`.
`secret`is used for symmetric algorithms and `private` and `public` are used
with asymmetric algorithms.

#### extractable
Specifies if this key can be extracted using `exportKey` or `wrapKey`. If this
value is false and those functions are called an exception will be thrown.

#### algorithm 
Is an object which can be one of the following types:
`AesKeyGenParams`, `RsaHashedKeyGenParams`, `EcKeyGenParams`, `HmacKeyGenParams`.

#### usages
`usages` is an Array with values of one or more of the following values:
```
encrypt: The key may be used to encrypt messages.
decrypt: The key may be used to decrypt messages.
sign: The key may be used to sign messages.
verify: The key may be used to verify signatures.
deriveKey: The key may be used in deriving a new key.
deriveBits: The key may be used in deriving bits.
wrapKey: The key may be used to wrap a key.
unwrapKey: The key may be used to unwrap a key

### AesKeyGenParams
Has two properties `name` and `length`.

`name` can be one of `AES-CBC`, `AES-CTR`, `AES-GCM`, or `AES-KW` (Key-Wrap)
which specifies the mode of operation.

`length` is the number of bits to generate and can be `128`, `192` or `256`.

### RsaHashedKeyGenParams
Are the parameters used when generating a RSA based key and is used for the
algoritms `RSASSA-PKCS1-v1_5`, `RSA-PSS`, or `RSA-OAEP`.

This object has the following properties:
`name` which is a string and one of `RSASSA-PKCS1-v1_5`, `RSA-PSS`, or `RSA-OAEP`.

`modulusLength` the length of the RSA modulus and should be at least 2048.

`publicExponent` is of type Uint8Array. 

`hash` is the name of the digest function to use and can be one of `SHA-256`,
`SHA-384`, or `SHA-512`.

### EcKeyGenParams
Uses as parameters when the algorithm is either `ECDSA` or `ECDH`.

`name` can be one of `ECDSA` or `ECDH`.

`namedCurve` the elliptic curve to use and can be one of `P-256`, `P-384`, or
`P-512`.


### HmacKeyGenParams
Used when the algorithm is `HMAC`.

`name` should be `HMAC`.

`hash` is the name of the digest function to use and can be one of `SHA-1`,
`SHA-256`, `SHA-384`, or `SHA-512`.

`length` is an optional length in bits of the key. 

### exportKey
Takes a `CryptoKey` and produces it in a portable external format:
```js
const result = crypto.subtle.exportKey(format, key);
```
The key is not encrypted, if that is desired then use `wrapKey` instead.

### importKey
Takes a key in external format and returns it as a `CryptoKey`.
```js
crypto.subtle.importKey(format,
                        keyData,
                        algorithm,
                        extractable,
                        keyUsages);
```
`format` can be `raw`, `pkcs8`, `spki`, or `jwk` (JSON Web Key format).


`keyUsages` can be any of the values specified in CryptoKey.usages.

The name subtle is to reflect that many of the algorithms have subtle usage
requirements in order to provide the required algorithmic security guarantees.

```js
window.crypto.getRandomValues();
```

### wrapKey
This function will call exportKey and then encrypt the result from that call.
This produces a key in a portable format that is encrypted.
```js
const result = crypto.subtle.wrapKey(format, key, wrappingKey, wrapAlgo);
```

### encrypt
Encrypts the plaintext (`data` below) using the specified algorithm and key:
```js
const result = crypto.subtle.encrypt(algorithm, key, data);
```
The result is a promise what when fulfilled will be an ArrayBuffer.

