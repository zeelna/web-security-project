package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	if len(plaintext) == 0 {
		return EncryptedPayload{}, errors.New("invalid plaintext")
	}

	// AEG-GCM
	// 1. Create new cipher block
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	// 2. Use cipher block to create a new GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}

	// Generate 12-byte nonce that will be used whenever AES256 key is used.
	//Why: Leverage AES' Galois-Counter-Mode to avoid resuing same symmetric key each time we encrypt
	nonceSize := aesgcm.NonceSize()
	// nonceSize := 12
	nonce := make([]byte, nonceSize)
	read, err := rand.Read(nonce)
	if err != nil || read != len(nonce) {
		return EncryptedPayload{}, errors.New("invalid nonce")
	}

	// 3. Use GCM to encrypt the plain (implements AEAD interface for industry-required 'Authenticated Encryption')
	seal := aesgcm.Seal(nil, nonce, plaintext, nil)
	authTag := seal[len(seal)-16:]    // last 16-bytes are AuthTag
	ciphertext := seal[:len(seal)-16] // all before that is the CipherText

	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    authTag,
		Ciphertext: ciphertext,
	}, nil // nil is 'no-error' here
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	// Reject payloads without 12-byte nonce, and without 16-byte authentication tag
	if len(payload.Nonce) != 12 {
		return nil, errors.New("invalid nonce")
	}
	if len(payload.AuthTag) != 16 {
		return nil, errors.New("invalid authentication tag")
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// The safest pattern in Go for concatenating two byte slices without aliasing risk is to explicitly allocate a new slice with make, sized to fit both, then copy each piece in:
	ciphertextSeal := make([]byte, len(payload.Ciphertext)+len(payload.AuthTag)) // make([]byte, len(a)+len(b)) allocates a brand new backing array, exactly big enough. No leftover capacity from anywhere else.
	copy(ciphertextSeal, payload.Ciphertext)                                     // copy(combined, a) copies a's bytes into the start of combined.
	copy(ciphertextSeal[len(payload.Ciphertext):], payload.AuthTag)              // copy(combined[len(a):], b) copies b's bytes into the remaining space, right after where a ended.
	// This guarantees combined doesn't share memory with a or b, so there's no risk of overwriting either one's original data.

	plaintext, err := aesgcm.Open(nil, payload.Nonce, ciphertextSeal, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, err
}
