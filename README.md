PBEWithMD5AndTripleDES java com.sun.crypto.provider implementation (JSE) using golang


Usage example:

```golang

import (
    tripleDES "github.com/ebirukov/PBEWithMD5AndTripleDES"
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
    
    encrypted := enc.Encrypt(originalText)
    fmt.Printf("encrypted data: % #x\n", encrypted)
    
    decrypted := dec.Decrypt(encrypted)
    //print decrypted secret string: mysecret_content
    fmt.Printf("decrypted secret string: %+v\n", string(decrypted))
}

```

Java equivalence:

```java
keySpec = new PBEKeySpec(password.toCharArray(), salt, iterations);
key = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES").generateSecret(keySpec);
ecipher = Cipher.getInstance(key.getAlgorithm());
dcipher = Cipher.getInstance(key.getAlgorithm());
ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

byte[] enc = ecipher.doFinal(originalText);
String res = Base64.getEncoder().encodeToString(enc);
System.out.println("encrypted " + res);

byte[] dec = Base64.getDecoder().decode(res);
dec = dcipher.doFinal(dec);
System.out.println("decrypted " + dec);

```