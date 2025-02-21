// examples/main.go

package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/zhenfeizhang/falcon-go/falcon" // Using local module path
)

func main() {
	// Generate a key pair for Falcon-512 (logN = 9)
	// For Falcon-1024, use logN = 10
	keyPair, err := falcon.GenerateKeyPair(9)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	fmt.Printf("Generated Falcon-512 key pair:\n")
	fmt.Printf("Public key size: %d bytes\n", len(keyPair.PublicKey))
	fmt.Printf("Private key size: %d bytes\n", len(keyPair.PrivateKey))

	// Sign a message using different signature formats
	message := []byte("Hello, Falcon!")

	// Try different signature types
	sigTypes := []struct {
		name string
		typ  int
	}{
		{"Compressed", falcon.SigCompressed},
		{"Padded", falcon.SigPadded},
		{"Constant-Time", falcon.SigCT},
	}

	for _, st := range sigTypes {
		// Generate signature
		signature, err := falcon.Sign(message, keyPair.PrivateKey, st.typ)
		if err != nil {
			log.Fatalf("Failed to create %s signature: %v", st.name, err)
		}

		fmt.Printf("\n%s signature:\n", st.name)
		fmt.Printf("Signature size: %d bytes\n", len(signature))

		fmt.Printf("First 64 bytes: %s\n", hex.EncodeToString(signature[:64]))

		// Verify signature
		err = falcon.Verify(signature, message, keyPair.PublicKey, st.typ)
		if err != nil {
			log.Fatalf("Failed to verify %s signature: %v", st.name, err)
		}
		fmt.Printf("Signature verified successfully\n")

		// Demonstrate invalid signature detection
		modifiedMessage := append([]byte{}, message...)
		modifiedMessage[0]++
		err = falcon.Verify(signature, modifiedMessage, keyPair.PublicKey, st.typ)
		if err != nil {
			fmt.Printf("As expected, verification failed for modified message: %v\n", err)
		}
	}

	// Demonstrate key size retrieval
	logN, err := falcon.GetLogN(keyPair.PublicKey)
	if err != nil {
		log.Fatalf("Failed to get logN: %v", err)
	}
	fmt.Printf("\nKey degree (logN): %d (Falcon-%d)\n", logN, 1<<logN)
}

// Output example:
// Generated Falcon-512 key pair:
// Public key size: 897 bytes
// Private key size: 1281 bytes
//
// Compressed signature:
// Signature size: 666 bytes
// First 32 bytes: 3ace...
// Signature verified successfully
// As expected, verification failed for modified message: invalid signature
//
// Padded signature:
// Signature size: 666 bytes
// First 32 bytes: 3bdf...
// Signature verified successfully
// As expected, verification failed for modified message: invalid signature
//
// Constant-Time signature:
// Signature size: 809 bytes
// First 32 bytes: 3cef...
// Signature verified successfully
// As expected, verification failed for modified message: invalid signature
//
// Key degree (logN): 9 (Falcon-512)
