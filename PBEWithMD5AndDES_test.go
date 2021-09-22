package PBEWithMD5AndTripleDES

import (
	"reflect"
	"testing"
)

func TestCipher_Decrypt(t *testing.T) {
	password := []byte{'m','y','p','a','s','s','w','o','r','d'}
	params := GeneratePBEParams(2000)
	encodedParams := params.Encode()
	cipher, _ := NewDecryptCipher(password, encodedParams)
	type args struct {
		dst []byte
		src []byte
	}
	tests := []struct {
		name    string
		cipher  Cipher
		args    args
		wantErr bool
	}{
		{

		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := cipher.Decrypt(tt.args.dst, tt.args.src); (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCipher_Encrypt(t *testing.T) {
	password := []byte{'m','y','p','a','s','s','w','o','r','d'}
	params := GeneratePBEParams(2000)
	cipher := NewEncryptCipher(password, params)
	type args struct {
		dst []byte
		src []byte
	}
	tests := []struct {
		name    string
		cipher  Cipher
		args    args
		wantErr bool
	}{
		{
			"case",
			*cipher,
			args{
				dst: []byte{0x6d, 0x79, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74},
				src: []byte{'m','y','s','e','c','r','e','t'},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := cipher.Encrypt(tt.args.dst, tt.args.src); (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewCipher(t *testing.T) {
	type args struct {
		password      []byte
		encodedParams []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *Cipher
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDecryptCipher(tt.args.password, tt.args.encodedParams)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDecryptCipher() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDecryptCipher() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPBEParams(t *testing.T) {
	type args struct {
		encodedParams []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *PBEParams
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodePBEParams(tt.args.encodedParams)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodePBEParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecodePBEParams() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getDerivedKey(t *testing.T) {
	type args struct {
		password []byte
		salt     []byte
		count    int
	}
	tests := []struct {
		name  string
		args  args
		want  []byte
		want1 []byte
	}{
		{
			"case1",
			args{
				password: []byte{'m','y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'},
				salt: []byte{0x69, 0xea, 0xff, 0x28, 0x65, 0x85, 0x0a, 0x68},
				count:    2000,
			},
			[]byte{0x8c,0xe5,0x38,0xd7,0x99,0xf2,0x39,0xe7,
				0x70,0x03,0x4b,0xe6,0xbf,0xd3,0x81,0x94,
				0x2f,0xa3,0xee,0xcd,0x18,0xbf,0xa7,0xcb},
			[]byte{0x36,0x91,0x08,0x2b,0xf4,0x99,0x2e,0x92},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := getDerivedKey(tt.args.password, tt.args.salt, tt.args.count)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getDerivedKey() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("getDerivedKey() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
