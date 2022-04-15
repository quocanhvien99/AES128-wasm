## Usage
```js
const aes = require('aes128-wasm');

aes().then(aesApi => {
    const { enc, dec } = aesApi;
    // encrypt and decrypt here
});
```