package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/anyproto/any-sync/util/crypto"
	"github.com/anyproto/anytype-heart/pkg/lib/crypto/symmetric"
	"github.com/anyproto/anytype-heart/pkg/lib/crypto/symmetric/cfb"
	"crypto/aes"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: decrypt <encrypted-file> <output-file>")
		return
	}

	// Your 12-word seed phrase
	mnemonic := "mean bike country rigid place inherit fiber panel hire rapid board move"

	// Derive account keys from mnemonic (index 0 = first account)
	derivationResult, err := crypto.Mnemonic(mnemonic).DeriveKeys(0)
	if err != nil {
		fmt.Printf("Error deriving keys: %v\n", err)
		return
	}

	// Read encrypted file
	encryptedData, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	// Try decrypting with account key
	decryptedData, err := derivationResult.Identity.Decrypt(encryptedData)
	if err != nil {
		fmt.Printf("Error decrypting with account key: %v\n", err)
		// Could also try with derivationResult.MasterKey.Decrypt() if needed
		return
	}

	// Write decrypted data
	err = ioutil.WriteFile(os.Args[2], decryptedData, 0644)
	if err != nil {
		fmt.Printf("Error writing decrypted file: %v\n", err)
		return
	}

	fmt.Println("File decrypted successfully!")
}