package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
)

const (
	KEYS_FOLDER     = "./keys"
	KeyType_PRIVATE = "private"
	KeyType_PUBLIC  = "public"
	Ext_PRIVATE     = ".key"
	Ext_PUBLIC      = ".pub"
	PemType_PRIVATE = "RSA PRIVATE KEY"
	PemType_PUBLIC  = "RSA PUBLIC KEY"
)

func main() {
	args, name, mode, msg := os.Args[1:], "guest", "", ""
	mode = strings.ToLower(args[0])
	if mode != "encrypt" && mode != "decrypt" && mode != "init" {
		log.Fatalf("invalid method: %s", mode)
	}
	if len(args) > 1 && args[1] == "--name" && args[2] != "" {
		name = args[2]
		msg = strings.Join(args[3:], " ")
	} else {
		msg = strings.Join(args[1:], " ")
	}

	switch mode {
	case "init":
		initialize(name)
		break
	case "encrypt":
		encrypt(name, msg)
		break
	case "decrypt":
		decrypt(name, msg)
		break
	}
}

func initialize(name string) {
	validateKeysRepo()

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	failOnError(err, "fail to generate rsa key pair")

	privKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  PemType_PRIVATE,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	pubKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  PemType_PUBLIC,
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})

	exportKey(name, KeyType_PRIVATE, privKeyBytes)
	exportKey(name, "KeyType_PUBLIC", pubKeyBytes)
	fmt.Printf("new encryption created, name: %s\n", name)
}

func encrypt(name string, msg string) {
	publicKey := importPublicKey(name)
	bytes, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(msg))
	failOnError(err, "failed to encrypt the msg")

	encoded := make([]byte, hex.EncodedLen(len(bytes)))
	hex.Encode(encoded, bytes)
	fmt.Println(string(encoded))
}

func decrypt(name string, msg string) {
	bmsg := []byte(msg)
	decoded := make([]byte, hex.DecodedLen(len(bmsg)))
	_, err := hex.Decode(decoded, bmsg)
	failOnError(err, "failed to decode the message!")

	privateKey := importPrivateKey(name)
	bytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, decoded)
	failOnError(err, "unable to decrypt the msg\nplease make sure you're using the right name\ncurrent name: "+name)
	fmt.Println(string(bytes))
}

func validateKeysRepo() {
	if dir, err := os.Open(path.Join(KEYS_FOLDER)); err != nil {
		if err = os.Mkdir(path.Join(KEYS_FOLDER), 0777); err != nil {
			failOnError(err, "Unable to create `tmp` dir")
		} else {
			dir.Close()
		}
	} else {
		dir.Close()
	}
}

func exportKey(name string, keyType string, key []byte) {
	ext := Ext_PUBLIC
	if keyType == KeyType_PRIVATE {
		ext = Ext_PRIVATE
	}
	filepath := path.Join(KEYS_FOLDER, name+ext)
	if _, err := os.Stat(filepath); err != nil && errors.Is(err, os.ErrNotExist) {
		file, err := os.Create(filepath)
		failOnError(err, "unable to create file: %s", filepath)
		_, err = file.Write(key)
		failOnError(err, "unable to write in the file: %s", filepath)
	} else {
		err = os.WriteFile(filepath, key, os.ModeAppend)
		failOnError(err, "unable to write in the file: %s", filepath)
	}
}

func importPrivateKey(name string) *rsa.PrivateKey {
	filepath := path.Join(KEYS_FOLDER, name+Ext_PRIVATE)
	if _, err := os.Stat(filepath); err != nil && errors.Is(err, os.ErrNotExist) {
		log.Panicf("no existing encryption for: %s", name)
	}
	bytes, err := os.ReadFile(filepath)
	failOnError(err, "unable to read file: %s", filepath)

	block, _ := pem.Decode(bytes)
	if block == nil {
		log.Panicf("unable to pem.Decode(): %s", filepath)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	failOnError(err, "unable to parse private key from: %s", filepath)
	return privateKey
}

func importPublicKey(name string) *rsa.PublicKey {
	filepath := path.Join(KEYS_FOLDER, name+Ext_PUBLIC)
	if _, err := os.Stat(filepath); err != nil && errors.Is(err, os.ErrNotExist) {
		log.Panicf("no existing encryption for: %s", name)
	}
	bytes, err := os.ReadFile(filepath)
	failOnError(err, "unable to read file: %s", filepath)

	block, _ := pem.Decode(bytes)
	if block == nil {
		log.Panicf("unable to pem.Decode(): %s", filepath)
	}
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	failOnError(err, "unable to parse public key from: %s", filepath)
	return publicKey
}

func failOnError(err error, msg string, rest ...string) {
	if err != nil {
		fmsg := fmt.Sprintf(msg, rest)
		log.Panicf("%s | error: %s", fmsg, err)
	}
}
