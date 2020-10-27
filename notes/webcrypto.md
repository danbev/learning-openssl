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

### importKey
Takes a key and returns it as a `CryptoKey`.
```js
crypto.subtle.importKey(format,
                        keyData,
                        algorithm,
                        extractable,
                        keyUsages);
```
`format` can be `raw`, `pkcs8`, `spki`, or `jwk` (JSON Web Key format).


`keyUsages` is an Array with values of one or more of the following values:
```
encrypt: The key may be used to encrypt messages.
decrypt: The key may be used to decrypt messages.
sign: The key may be used to sign messages.
verify: The key may be used to verify signatures.
deriveKey: The key may be used in deriving a new key.
deriveBits: The key may be used in deriving bits.
wrapKey: The key may be used to wrap a key.
unwrapKey: The key may be used to unwrap a key
```

The name subtle is to reflect that many of the algorithms have subtle usage
requirements in order to provide the required algorithmic security guarantees.

```js
window.crypto.getRandomValues();
```


