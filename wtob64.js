const fs = require('fs');

const wasmCode = fs.readFileSync('./main.wasm');
const encoded = wasmCode.toString('base64');
fs.writeFileSync('./base64.txt', encoded);
