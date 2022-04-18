## Usage

```js
const aes = require('aes-wasm-quocanhv');

aes().then((aesApi) => {
	const { enc, dec } = aesApi;
	// encrypt and decrypt here
	// Length of secret key should be 16, 24 or 32
	const cipher = enc(key, plainText, iv, mode);
	const plaintext = dec(key, cipherText, iv, mode);
});
```
