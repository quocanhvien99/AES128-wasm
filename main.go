package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"syscall/js"
)

func encrypt(this js.Value, msg []js.Value) interface{} {
	text := []byte(msg[0].String())
    key := encodeKey(msg[1].String())

    if len(msg[1].String()) != 16 {
        js.Global().Call("alert", "Length of secret key should be 16 for 128 bits key size")
        return nil
    }

    // generate a new aes cipher using our 32 byte long key
    c, err := aes.NewCipher(key)
    // if there are any errors, handle them
    if err != nil {
        fmt.Println(err)
    }

    // gcm or Galois/Counter Mode, is a mode of operation
    // for symmetric key cryptographic block ciphers
    // - https://en.wikipedia.org/wiki/Galois/Counter_Mode
    gcm, err := cipher.NewGCM(c)
    // if any error generating new GCM
    // handle them
    if err != nil {
        fmt.Println(err)
    }

    // creates a new byte array the size of the nonce
    // which must be passed to Seal
    nonce := make([]byte, gcm.NonceSize())
    // populates our nonce with a cryptographically secure
    // random sequence
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        fmt.Println(err)
    }

    // here we encrypt our text using the Seal function
    // Seal encrypts and authenticates plaintext, authenticates the
    // additional data and appends the result to dst, returning the updated
    // slice. The nonce must be NonceSize() bytes long and unique for all
    // time, for a given key.
	//buf := gcm.Seal(nonce, nonce, text, nil)
	//dst:= js.Global().Get("Uint8Array").New(len(buf))
	//js.CopyBytesToJS(dst, buf)
    
    return hex.EncodeToString(gcm.Seal(nonce, nonce, text, nil))
}

func decrypt(this js.Value, cipherhex []js.Value) interface{} {
	key := encodeKey(cipherhex[1].String())
	ciphertext, err := hex.DecodeString(cipherhex[0].String())
	//js.CopyBytesToGo(ciphertext, cipherbuf[0])
    if len(cipherhex[1].String()) != 16 {
        js.Global().Call("alert", "Length of secret key should be 16 for 128 bits key size")
        return nil
    }

    c, err := aes.NewCipher(key)
    if err != nil {
        fmt.Println(err)
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        fmt.Println(err)
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        fmt.Println(err)
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        fmt.Println(err)
    }
	return string(plaintext)
}

func main() {
	chann:=make(chan bool)

	js.Global().Set("enc", js.FuncOf(encrypt))
	js.Global().Set("dec", js.FuncOf(decrypt))

	<- chann
}

func encodeKey(keys string) []byte {
    var keylen = len(keys)
	key := make([]byte, keylen)
	for i := 0; i < keylen; i++ {
		key[keylen-i-1] = keys[i] << 2
	}
    return key
}