const aes = require('aes128-wasm');

aes().then((instance) => {
	const { enc, dec } = instance;

	const encrypt = (e) => {
		e.preventDefault();
		const key = e.currentTarget.querySelector('#key').value;
		const plainText = document.querySelector('#enc').value;
		const cipherHex = enc(plainText, key);
		console.log(cipherHex);
		document.querySelector('#enc-result').value = cipherHex;
	};
	document.querySelector('#encForm').addEventListener('submit', encrypt);

	const decrypt = (e) => {
		e.preventDefault();
		const key = e.currentTarget.querySelector('#key').value;
		const cipherText = document.querySelector('#dec').value;
		const plainText = dec(cipherText, key);
		document.querySelector('#dec-result').value = plainText;
	};
	document.querySelector('#decForm').addEventListener('submit', decrypt);
});
