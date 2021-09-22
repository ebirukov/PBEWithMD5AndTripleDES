package main

import (
	tripleDES "PBEWithMD5AndTripleDES"
	"fmt"
)

func main() {
	password := []byte("mypassword")
	originalText := []byte("mysecret_content")
	iterations := 2000

	params := tripleDES.GeneratePBEParams(iterations)
	enc := tripleDES.NewEncryptCipher(password, params)
	dec, err := tripleDES.NewDecryptCipher(password, params.Encode())
	if err != nil {
		panic(err.Error())
	}

	encrypted := make([]byte, len(originalText))
	enc.Encrypt(encrypted, originalText)
	fmt.Printf("encrypted data: % #x\n", encrypted)

	decrypted := make([]byte, len(encrypted))
	dec.Decrypt(decrypted, encrypted)
	//print decrypted secret string: mysecret_content
	fmt.Printf("decrypted secret string: %+v\n", string(decrypted))
}