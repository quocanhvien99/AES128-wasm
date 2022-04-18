const aes = require('./aes-WASM/index');

aes().then((instance) => {
	const { enc, dec } = instance;

	const encrypt = (e) => {
		e.preventDefault();
		const key = e.currentTarget.querySelector('#key').value;
		const iv = e.currentTarget.querySelector('#iv').value;
		const plainText = document.querySelector('#enc').value;
		const mode = document.querySelector('#mode').value;
		const cipherHex = enc(key, plainText, iv, mode);
		console.log(cipherHex);
		document.querySelector('#enc-result').value = cipherHex;
	};
	document.querySelector('#encForm').addEventListener('submit', encrypt);

	const decrypt = (e) => {
		e.preventDefault();
		const key = e.currentTarget.querySelector('#key').value;
		const iv = e.currentTarget.querySelector('#iv').value;
		const cipherText = document.querySelector('#dec').value;
		const mode = document.querySelector('#mode').value;
		const plainText = dec(key, cipherText, iv, mode);
		document.querySelector('#dec-result').value = plainText;
	};
	document.querySelector('#decForm').addEventListener('submit', decrypt);
});
