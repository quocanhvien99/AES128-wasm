package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"syscall/js"
)  
  
func main() {  
	chann:=make(chan bool)
	
	js.Global().Set("GCMencrypt", js.FuncOf(GCM_encrypt))

	<-chann
}  

func GCM_encrypt(this js.Value, params []js.Value) interface{} {  
	block, err := aes.NewCipher([]byte(params[0].String()))  
	if err != nil {  
	   panic(err.Error())  
	}  
	aesgcm, err := cipher.NewGCM(block)  
	if err != nil {  
	   panic(err.Error())  
	}  
	ciphertext := aesgcm.Seal(nil, []byte(params[2].String()), []byte(params[1].String()), []byte(params[3].String()))  
	return hex.EncodeToString(ciphertext)  
 }  
   
 func GCM_decrypt(this js.Value, params []js.Value) interface{} {  
	ciphertext, _ := hex.DecodeString(params[1].String())  
	block, err := aes.NewCipher([]byte(params[0].String()))  
	if err != nil {  
	   panic(err.Error())  
	}  
	aesgcm, err := cipher.NewGCM(block)  
	if err != nil {  
	   panic(err.Error())  
	}  
	plaintext, err := aesgcm.Open(nil, []byte(params[2].String()), ciphertext, []byte(params[3].String()))  
	if err != nil {  
	   panic(err.Error())  
	}  
	s := string(plaintext[:])  
	return s  
 }

 func CBCEncrypter(this js.Value, params []js.Value) interface{} {  
	block, err := aes.NewCipher([]byte(params[0].String()))  
	if err != nil {  
	   panic(err)  
	}   
	// include it at the beginning of the ciphertext.  
	ciphertext := make([]byte, aes.BlockSize+len(params[1].String()))  
	mode := cipher.NewCBCEncrypter(block, []byte(params[2].String()))  
	mode.CryptBlocks(ciphertext[aes.BlockSize:], []byte(params[1].String()))  
	return hex.EncodeToString(ciphertext)  
 }  
 
 func CBCDecrypter(this js.Value, params []js.Value) interface{} {  
	ciphertext, _ := hex.DecodeString(params[1].String())  
	block, err := aes.NewCipher([]byte(params[0].String()))  
	if err != nil {  
	   panic(err)  
	}  
	ciphertext = ciphertext[aes.BlockSize:]  
	// CBC mode always works in whole blocks.  
   if len(ciphertext)%aes.BlockSize != 0 {  
	   panic("ciphertext is not a multiple of the block size")  
	}  
	mode := cipher.NewCBCDecrypter(block, []byte(params[2].String()))  
	// CryptBlocks can work in-place if the two arguments are the same.  
	mode.CryptBlocks(ciphertext, ciphertext)  
	s := string(ciphertext[:])  
   
	return s  
 }
 func CFBEncrypter(this js.Value, params []js.Value) interface{} {  
	block, err := aes.NewCipher([]byte(params[0].String()))  
	if err != nil {  
	   panic(err)  
	}  
	ciphertext := make([]byte, aes.BlockSize+len(params[1].String()))  
	stream := cipher.NewCFBEncrypter(block, []byte(params[2].String()))  
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(params[1].String()))  
	return hex.EncodeToString(ciphertext)  
 }  
 
 func CFBDecrypter(this js.Value, params []js.Value) interface{} {  
   
	ciphertext, _ := hex.DecodeString(params[1].String())  
	block, err := aes.NewCipher([]byte(params[0].String()))  
	if err != nil {  
	   panic(err)  
	}  
	ciphertext = ciphertext[aes.BlockSize:]  
   
	stream := cipher.NewCFBDecrypter(block, []byte(params[2].String()))  
	// XORKeyStream can work in-place if the two arguments are the same.  
   stream.XORKeyStream(ciphertext, ciphertext)  
	s := string(ciphertext[:])  
   
	return s  
 }

 func CTREncrypter(this js.Value, params []js.Value) interface{} {  
  
	block, err := aes.NewCipher([]byte(params[0].String()))  
	if err != nil {  
	   panic(err)  
	}  
	ciphertext := make([]byte, aes.BlockSize+len(params[1].String()))  
	stream := cipher.NewCTR(block, []byte(params[2].String()))  
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))  
	return hex.EncodeToString(ciphertext)  
 }  
 
 func CTRDecrypter(this js.Value, params []js.Value) interface{} {  
	ciphertext, _ := hex.DecodeString(params[1].String())  
	block, err := aes.NewCipher([]byte(params[0].String()))  
	if err != nil {  
	   panic(err)  
	}  
	ciphertext = ciphertext[aes.BlockSize:]  
	// CBC mode always works in whole blocks.  
   if len(ciphertext)%aes.BlockSize != 0 {  
	   panic("ciphertext is not a multiple of the block size")  
	}  
	mode := cipher.NewCTR(block, []byte(params[2].String()))  
	mode.XORKeyStream(ciphertext, ciphertext)  
	s := string(ciphertext[:])  
   
	return s  
 }

 func OFBEncrypter(key string, plaintext string, iv []byte    this js.Value, params []js.Value) interface{} {  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err)  
	}  
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))  
	stream := cipher.NewOFB(block, iv)  
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))  
	return hex.EncodeToString(ciphertext)  
 }  
   
 func OFBDecrypter(key string,ct string,iv []byte     this js.Value, params []js.Value) interface{} {  
	ciphertext, _ := hex.DecodeString(ct)  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err)  
	}  
	ciphertext = ciphertext[aes.BlockSize:]  
	// CBC mode always works in whole blocks.  
	if len(ciphertext)%aes.BlockSize != 0 {  
	   panic("ciphertext is not a multiple of the block size")  
	}  
	mode := cipher.NewOFB(block, iv)  
	mode.XORKeyStream(ciphertext, ciphertext)  
	s := string(ciphertext[:])  
	return s  
 }