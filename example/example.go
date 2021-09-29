package main

import (
	"fmt"
	tripleDES "github.com/ebirukov/PBEWithMD5AndTripleDES"
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

	encrypted := enc.Encrypt(originalText)
	fmt.Printf("encrypted data: % #x\n", encrypted)

	decrypted := dec.Decrypt(encrypted)
	//print decrypted secret string: mysecret_content
	fmt.Printf("decrypted secret string: %+v\n", string(decrypted))
}
