package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/anyproto/any-sync/util/crypto"
)

const anytypeMetadataPath = "m/SLIP-0021/anytype/account/metadata"

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

	fmt.Printf("File size: %d bytes\n", len(encryptedData))
	fmt.Printf("First 32 bytes: %x\n", encryptedData[:min(32, len(encryptedData))])

	// Try multiple decryption approaches
	success := false

	// 1. Try deriving symmetric keys from private keys
	var keys []crypto.SymKey

	// Try deriving account metadata key from Identity
	if accountKey, err := deriveAccountEncKey(derivationResult.Identity); err == nil {
		keys = append(keys, accountKey)
	}

	// Try deriving from master key
	if masterEncKey, err := deriveAccountEncKey(derivationResult.MasterKey); err == nil {
		keys = append(keys, masterEncKey)
	}

	// Try CFB decryption with different keys
	for i, key := range keys {
		fmt.Printf("\nTrying key %d (CFB with zero IV)...\n", i+1)
		if decryptedData, err := tryDecryptCFB(encryptedData, key); err == nil {
			success = true
			fmt.Printf("✓ Decryption successful with key %d (CFB)!\n", i+1)
			if err := writeDecryptedData(os.Args[2], decryptedData); err != nil {
				fmt.Printf("Error writing file: %v\n", err)
				return
			}
			break
		} else {
			fmt.Printf("✗ Failed with key %d (CFB): %v\n", i+1, err)
		}
	}

	// Try direct decryption with symmetric keys
	if !success {
		for i, key := range keys {
			fmt.Printf("\nTrying key %d (Direct decryption)...\n", i+1)
			if decryptedData, err := key.Decrypt(encryptedData); err == nil {
				success = true
				fmt.Printf("✓ Decryption successful with key %d (Direct)!\n", i+1)
				if err := writeDecryptedData(os.Args[2], decryptedData); err != nil {
					fmt.Printf("Error writing file: %v\n", err)
					return
				}
				break
			} else {
				fmt.Printf("✗ Failed with key %d (Direct): %v\n", i+1, err)
			}
		}
	}

	if !success {
		fmt.Println("\n❌ All decryption attempts failed. The file might use a different encryption scheme or key derivation.")
		fmt.Println("\nPossible reasons:")
		fmt.Println("- File might be encrypted with a space-specific key")
		fmt.Println("- File might use a different encryption algorithm")
		fmt.Println("- File might be a different type of Anytype data")
		fmt.Println("- File might require additional IPFS/DAG context")
	} else {
		fmt.Println("\n✅ File decrypted successfully!")
	}
}

func deriveAccountEncKey(accKey crypto.PrivKey) (crypto.SymKey, error) {
	raw, err := accKey.Raw()
	if err != nil {
		return nil, err
	}
	return crypto.DeriveSymmetricKey(raw, anytypeMetadataPath)
}

func tryDecryptCFB(encryptedData []byte, key crypto.SymKey) ([]byte, error) {
	// Get raw key
	rawKey, err := key.Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}
	
	if len(rawKey) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32, got %d", len(rawKey))
	}
	
	// Create AES cipher
	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	
	// Use zero IV as in the anytype-heart codebase
	iv := make([]byte, aes.BlockSize)
	
	// Create CFB decrypter
	stream := cipher.NewCFBDecrypter(block, iv)
	
	// Decrypt data
	decryptedData := make([]byte, len(encryptedData))
	stream.XORKeyStream(decryptedData, encryptedData)
	
	// Basic validation - check if it looks like protobuf
	if err := validateDecryption(decryptedData); err != nil {
		return nil, fmt.Errorf("decryption validation failed: %w", err)
	}
	
	return decryptedData, nil
}

func validateDecryption(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}
	
	// Check if it looks like protobuf data
	// Protobuf messages start with field tags where:
	// - bits 0-2 are wire type (0-5 are valid)
	// - bits 3+ are field number (must be > 0)
	firstByte := data[0]
	wireType := firstByte & 0x07
	fieldNumber := firstByte >> 3
	
	if wireType > 5 {
		return fmt.Errorf("invalid protobuf wire type: %d", wireType)
	}
	
	if fieldNumber == 0 {
		return fmt.Errorf("invalid protobuf field number: 0")
	}
	
	// Additional check: look for printable characters or null bytes
	nullCount := 0
	printableCount := 0
	for i, b := range data {
		if i > 100 { // Only check first 100 bytes
			break
		}
		if b == 0 {
			nullCount++
		}
		if b >= 32 && b <= 126 {
			printableCount++
		}
	}
	
	// If too many nulls or no printable chars, might be gibberish
	checkLen := min(100, len(data))
	if nullCount > checkLen/2 && printableCount == 0 {
		return fmt.Errorf("decrypted data appears to be random bytes")
	}
	
	return nil
}

func writeDecryptedData(filename string, data []byte) error {
	fmt.Printf("\nDecrypted data information:\n")
	fmt.Printf("- Size: %d bytes\n", len(data))
	fmt.Printf("- First 32 bytes: %x\n", data[:min(32, len(data))])
	
	// Try to show first few bytes as ASCII if printable
	printable := ""
	for i, b := range data[:min(64, len(data))] {
		if b >= 32 && b <= 126 {
			printable += string(b)
		} else {
			printable += fmt.Sprintf("\\x%02x", b)
		}
		if i > 0 && i%16 == 0 {
			printable += "\n"
		}
	}
	fmt.Printf("- First bytes as text: %s\n", printable)
	
	return ioutil.WriteFile(filename, data, 0644)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}