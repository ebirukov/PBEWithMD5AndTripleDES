package PBEWithMD5AndTripleDES

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
)

type PBEParams struct {
	Salt []byte
	Iterations int
}

func (pbe PBEParams) Encode() (enc []byte) {
	var err error
	if enc, err = asn1.Marshal(pbe); err != nil {
		panic(fmt.Errorf("can't encode PBE parameters: %w", err))
	}
	return
}

const saltLength = 8

func GeneratePBEParams(iterations int) PBEParams {
	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		panic(fmt.Errorf("can't create salt %w", err))
	}
	return PBEParams{
		Salt:       salt,
		Iterations: iterations,
	}
}

func DecodePBEParams(encodedParams []byte) (*PBEParams, error) {
	pbe := new(PBEParams)
	_, err := asn1.Unmarshal(encodedParams, pbe)
	if err != nil {
		return nil, err
	}
	return pbe, nil
}

type Cipher struct {
	block cipher.Block
	iv []byte
}

//NewDecryptCipher construct decrypter cipher by PBE params and password
func NewDecryptCipher(password []byte, encodedParams []byte) (*Cipher, error) {
	pbeParams, err := DecodePBEParams(encodedParams)
	if err != nil {
		return nil, err
	}
	cipher := new(Cipher)
	cipher.init(password, *pbeParams)
	return cipher, nil
}

//NewEncryptCipher construct encryptor cipher by PBE params and password
func NewEncryptCipher(password []byte, params PBEParams) *Cipher {
	cipher := new(Cipher)
	cipher.init(password, params)
	return cipher
}

func (c *Cipher) Encrypt(dst, src []byte) error {
	if  len(dst) < len(src) {
		return errors.New("dst size must equal src size")
	}
	enc := cipher.NewCBCEncrypter(c.block, c.iv)
	enc.CryptBlocks(dst, src)
	return nil
}

func (c *Cipher) Decrypt(dst, src []byte) error {
	if  len(dst) < len(src) {
		return errors.New("dst size must equal src size")
	}
	dec := cipher.NewCBCDecrypter(c.block, c.iv)
	dec.CryptBlocks(dst, src)
	return nil
}

func (c *Cipher) init(password []byte, params PBEParams) {
	var dk []byte
	dk, c.iv = getDerivedKey(password, params.Salt, params.Iterations)
	var err error
	c.block, err = des.NewTripleDESCipher(dk)
	if err != nil {
		panic(err.Error())
	}
	return
}


//getDerivedKey 
/*
 Here's how this algorithm works:
      1. split salt in two halves. If the two halves are identical, invert(*) the first half.
      2. Concatenate password with each of the halves.
      3. Digest each concatenation with c iterations, where c is the iterationCount.
		 Concatenate the output from each digest round with the password,
         and use the result as the input to the next digest operation. The digest
         algorithm is MD5.
      4. After c iterations, use the 2 resulting digests as follows: The 16 bytes of the first digest and the 1st 8 bytes of the 2nd digest
         form the triple DES key, and the last 8 bytes of the 2nd digest form the IV.
*/
func getDerivedKey(password []byte, salt []byte, count int) ([]byte, []byte) {
	saltHalves := [][]byte{salt[:4], salt[4:]}
	var derived [2][]byte
	for i := 0; i < 2; i++ {
		derived[i] = saltHalves[i]
		for j := 0; j < count; j++ {
			r := md5.Sum(append(derived[i], password...))
			derived[i] = r[:]
		}
	}
	key := append(derived[0][:], derived[1][:8]...)
	iv := derived[1][8:]
	return key, iv
}