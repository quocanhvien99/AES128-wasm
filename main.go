package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"syscall/js"
)  
  
func main() {  
	chann:=make(chan bool)
	
	js.Global().Set("enc", js.FuncOf(encrypt))
	js.Global().Set("dec", js.FuncOf(decrypt))

	<- chann
} 

// encrypt(key, plaintext, iv, mode )
func encrypt(this js.Value, params []js.Value) interface{} {
    mode := params[3].String()

	//valid key
	key := params[0].String()
	err := validKey(key)
    if len(err) != 0 {
        js.Global().Call("alert",err)
        return nil
    }
	key = encodeKey(key)
	
	//valid iv
	err = validIV(params[2].String(), mode)
    if len(err) != 0 {
        js.Global().Call("alert",err)
        return nil
    }
	iv := []byte(params[2].String())

	plaintext := params[1].String()
	var cipher string

	switch mode {
		case "GCM":
			cipher = GCMEncrypter(key, plaintext, iv)
		case "CBC":
			cipher = CBCEncrypter(key, plaintext, iv)
		case "CFB":
			cipher = CFBEncrypter(key, plaintext, iv)
		case "CTR":
			cipher = CTREncrypter(key, plaintext, iv)
		case "OFB":
			cipher = OFBEncrypter(key, plaintext, iv)	
	}

	return cipher
}
// decrypt(key, cipher, iv, mode )
func decrypt(this js.Value, params []js.Value) interface{} {
    mode := params[3].String()

    //valid key
	key := params[0].String()
	err := validKey(key)
    if len(err) != 0 {
        js.Global().Call("alert",err)
        return nil
    }
	key = encodeKey(key)

	//valid iv
	err = validIV(params[2].String(), mode)
    if len(err) != 0 {
        js.Global().Call("alert",err)
        return nil
    }
	iv := []byte(params[2].String())

	cipher:=params[1].String()
	var plaintext string

	switch mode {
		case "GCM":
			plaintext = GCMDecrypter(key, cipher, iv)
		case "CBC":
			plaintext = CBCDecrypter(key, cipher, iv)
		case "CFB":
			plaintext = CFBDecrypter(key, cipher, iv)
		case "CTR":
			plaintext = CTRDecrypter(key, cipher, iv)
		case "OFB":
			plaintext = OFBDecrypter(key, cipher, iv)	
	}

	return plaintext
}

// Appends padding.
func pkcs7Pad(data []byte, blocklen int) ([]byte, string) {
    if blocklen <= 0 {
        return nil, "invalid blocklen"
    }
    padlen := 1
    for ((len(data) + padlen) % blocklen) != 0 {
        padlen = padlen + 1
    }

    pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
    return append(data, pad...), ""
}

// Returns slice of the original data without padding.
func pkcs7Unpad(data []byte, blocklen int) ([]byte, string) {
    if blocklen <= 0 {
        return nil, "invalid blocklen"
    }
    if len(data)%blocklen != 0 || len(data) == 0 {
        return nil, "invalid data len"
    }
    padlen := int(data[len(data)-1])
    if padlen > blocklen || padlen == 0 {
        return nil, "invalid padding"
    }
    // check padding
    pad := data[len(data)-padlen:]
    for i := 0; i < padlen; i++ {
        if pad[i] != byte(padlen) {
            return nil, "invalid padding"
        }
    }

    return data[:len(data)-padlen], ""
}
func GCMEncrypter(key string, plaintext string, iv []byte ) string {  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err.Error())  
	}  
	aesgcm, err := cipher.NewGCM(block)  
	if err != nil {  
	   panic(err.Error())  
	}  
	ciphertext := aesgcm.Seal(nil, iv, []byte(plaintext), nil)  
	return hex.EncodeToString(ciphertext)  
 }  
   
 func GCMDecrypter(key string,ct string,iv []byte) string {  
	ciphertext, _ := hex.DecodeString(ct)  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err.Error())  
	}  
	aesgcm, err := cipher.NewGCM(block)  
	if err != nil {  
	   panic(err.Error())  
	}  
	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)  
	if err != nil {  
	   panic(err.Error())  
	}  
	s := string(plaintext[:])  
	return s  
 }

 func CBCEncrypter(key string, plaintext string, iv []byte) string {  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err)  
	}   

	origData, _ := pkcs7Pad([]byte(plaintext), aes.BlockSize)

	// include it at the beginning of the ciphertext.  
	ciphertext := make([]byte, len(origData))  
	mode := cipher.NewCBCEncrypter(block, iv)  
	mode.CryptBlocks(ciphertext, origData)  
	return hex.EncodeToString(ciphertext)
 }  
 
 func CBCDecrypter(key string,ct string,iv []byte) string {  
	ciphertext, _ := hex.DecodeString(ct)  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err)  
	}  
	// CBC mode always works in whole blocks.  
   if len(ciphertext)%aes.BlockSize != 0 {  
	   panic("ciphertext is not a multiple of the block size")  
	}  
	mode := cipher.NewCBCDecrypter(block, iv)  
	origData := make([]byte, len(ciphertext))

	// CryptBlocks can work in-place if the two arguments are the same.  
	mode.CryptBlocks(origData, ciphertext)  
	origData, _ = pkcs7Unpad(origData, aes.BlockSize)
	s := string(origData)  
   
	return s
 }

 func CTREncrypter(key string, plaintext string, iv []byte) string {  
  
	block, err := aes.NewCipher([]byte(key)) 
	if err != nil {  
	   panic(err)  
	}  

	origData, _ := pkcs7Pad([]byte(plaintext), aes.BlockSize)

	ciphertext := make([]byte, len(origData))  
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, origData)  
	return hex.EncodeToString(ciphertext)  
 }  
 
 func CTRDecrypter(key string,ct string,iv []byte) string {  
	ciphertext, _ := hex.DecodeString(ct)  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err)  
	}  
	// CBC mode always works in whole blocks.  
   if len(ciphertext)%aes.BlockSize != 0 {  
	   panic("ciphertext is not a multiple of the block size")  
	}  
	mode := cipher.NewCTR(block, iv)  
	origData := make([]byte, len(ciphertext))

	mode.XORKeyStream(origData, ciphertext)  
	origData, _ = pkcs7Unpad(origData, aes.BlockSize)
	s := string(origData)  
   
	return s  
 }

 func OFBEncrypter(key string, plaintext string, iv []byte) string {  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err)  
	}  

	origData, _ := pkcs7Pad([]byte(plaintext), aes.BlockSize)

	ciphertext := make([]byte, len(origData))
	stream := cipher.NewOFB(block, iv)  
	stream.XORKeyStream(ciphertext, origData)  
	return hex.EncodeToString(ciphertext)  
 }  
   
   
   
 func OFBDecrypter(key string,ct string,iv []byte) string {  
	ciphertext, _ := hex.DecodeString(ct)  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {
	   panic(err)  
	}
	// CBC mode always works in whole blocks.  
	if len(ciphertext)%aes.BlockSize != 0 {  
	   panic("ciphertext is not a multiple of the block size")  
	}  
	mode := cipher.NewOFB(block, iv)  
	origData := make([]byte, len(ciphertext))

	mode.XORKeyStream(origData, ciphertext)  
	origData, _ = pkcs7Unpad(origData, aes.BlockSize)
	s := string(origData)  
	return s  
 }

 func CFBEncrypter(key string, plaintext string, iv []byte) string {  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err)  
	}  
	ciphertext := make([]byte, len(plaintext))  
	stream := cipher.NewCFBEncrypter(block, iv)  
	stream.XORKeyStream(ciphertext, []byte(plaintext))  
	return hex.EncodeToString(ciphertext)  
 }  
 
 func CFBDecrypter(key string,ct string,iv []byte) string {  
   
	ciphertext, _ := hex.DecodeString(ct)  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err)  
	}
   
	stream := cipher.NewCFBDecrypter(block, iv)  
	// XORKeyStream can work in-place if the two arguments are the same.  
   stream.XORKeyStream(ciphertext, ciphertext)  
	s := string(ciphertext[:])  
   
	return s  
 }

 func encodeKey(keys string) string {
    var keylen = len(keys)
	key := make([]byte, keylen)
	for i := 0; i < keylen; i++ {
		key[keylen-i-1] = keys[i] << 2
	}
    return string(key)
}
func validKey(key string) string {
    keylen:=len(key)
    if keylen != 16 && keylen!=24 && keylen!=32 {
        return "Length of secret key should be 16, 24 or 32"
    }
    return ""
}
func validIV(iv string, mode string) string {
    ivlen:=len(iv)
    if mode == "GCM" && ivlen != 12 {
        return "Length of iv should be 12"
    }
    if mode != "GCM" && ivlen != 16 {
        return "Length of iv should be 16"
    }
    return ""
}