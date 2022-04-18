package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)  

func main() {  
	 // 32 bit length key, Most be secured in production ENV  
   // No Hardcoding of the key  
   key := "myverystrongpasswordo32bitlength"  
   
   // IN OFB Mode the plaintext shoun't be Must be Block Size of AES (Multiple of 16)  
   // Other WIse Paddign needs to be perfomed  
   plainText := "Hello sdf sdf sdfsfsdf" 
   fmt.Printf("Original Text:  %s\n",plainText)   
  
   //IV Length Must be equal to Block Size.  
//    iv := make([]byte, aes.BlockSize)  
//    if _, err := io.ReadFull(rand.Reader, iv); err != nil {  
//       panic(err.Error())  
//    }  
	iv:=[]byte("0123456789abcdef")

	
	ciphertext := CBCEncrypter(key,plainText,iv)  
	fmt.Printf("CBC Encrypted Text:  %s\n", ciphertext)  
	ret := CBCDecrypter(key,ciphertext,iv)  
	fmt.Printf("CBC Decrypted Text:  %s\n", ret)

	ciphertext = GCMEncrypter(key,plainText,[]byte("123456789012"))  
   fmt.Printf("GCM Encrypted Text:  %s\n", ciphertext)  
   ret = GCMDecrypter(key,ciphertext,[]byte("123456789012"))  
   fmt.Printf("GCM Decrypted Text:  %s\n", ret)

   ciphertext = CTREncrypter(key,plainText,iv)  
   fmt.Printf("CTR Encrypted Text:  %s\n", ciphertext)  
   ret = CTRDecrypter(key,ciphertext,iv)  
   fmt.Printf("CTR Decrypted Text:  %s\n", ret)

   ciphertext = OFBEncrypter(key,plainText,iv)  
   fmt.Printf("OFB Encrypted Text:  %s\n", ciphertext)  
   ret = OFBDecrypter(key,ciphertext,iv)  
   fmt.Printf("OFB Decrypted Text:  %s\n", ret)

   ciphertext = CFBEncrypter(key,plainText,iv)  
   fmt.Printf("CFB Encrypted Text:  %s\n", ciphertext)  
   ret = CFBDecrypter(key,ciphertext,iv)  
   fmt.Printf("CFB Decrypted Text:  %s\n", ret)

} 

// Appends padding.
func pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
    if blocklen <= 0 {
        return nil, fmt.Errorf("invalid blocklen %d", blocklen)
    }
    padlen := 1
    for ((len(data) + padlen) % blocklen) != 0 {
        padlen = padlen + 1
    }

    pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
    return append(data, pad...), nil
}

// Returns slice of the original data without padding.
func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
    if blocklen <= 0 {
        return nil, fmt.Errorf("invalid blocklen %d", blocklen)
    }
    if len(data)%blocklen != 0 || len(data) == 0 {
        return nil, fmt.Errorf("invalid data len %d", len(data))
    }
    padlen := int(data[len(data)-1])
    if padlen > blocklen || padlen == 0 {
        return nil, fmt.Errorf("invalid padding")
    }
    // check padding
    pad := data[len(data)-padlen:]
    for i := 0; i < padlen; i++ {
        if pad[i] != byte(padlen) {
            return nil, fmt.Errorf("invalid padding")
        }
    }

    return data[:len(data)-padlen], nil
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

	origData, err := pkcs7Pad([]byte(plaintext), aes.BlockSize)

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
	origData, err = pkcs7Unpad(origData, aes.BlockSize)
	s := string(origData)  
   
	return s
 }

 func CTREncrypter(key string, plaintext string, iv []byte) string {  
  
	block, err := aes.NewCipher([]byte(key)) 
	if err != nil {  
	   panic(err)  
	}  

	origData, err := pkcs7Pad([]byte(plaintext), aes.BlockSize)

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
	ciphertext = ciphertext  
	// CBC mode always works in whole blocks.  
   if len(ciphertext)%aes.BlockSize != 0 {  
	   panic("ciphertext is not a multiple of the block size")  
	}  
	mode := cipher.NewCTR(block, iv)  
	origData := make([]byte, len(ciphertext))

	mode.XORKeyStream(origData, ciphertext)  
	origData, err = pkcs7Unpad(origData, aes.BlockSize)
	s := string(origData)  
   
	return s  
 }

 func OFBEncrypter(key string, plaintext string, iv []byte) string {  
	block, err := aes.NewCipher([]byte(key))  
	if err != nil {  
	   panic(err)  
	}  

	origData, err := pkcs7Pad([]byte(plaintext), aes.BlockSize)

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
	origData, err = pkcs7Unpad(origData, aes.BlockSize)
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