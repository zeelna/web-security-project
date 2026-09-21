package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const MaxLength = 128
const RequiredMemory = 19 * 1024
const Threads = 1
const Time = 2
const KeyLen = 32

func Hash(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password too short")
	}

	if len(password) > MaxLength {
		return "", errors.New("password too long")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey([]byte(password), salt, Time, RequiredMemory, Threads, KeyLen)
	return encodeArgon2idHash(argon2idHash{
		version:     argon2.Version,
		salt:        salt,
		derivedKey:  derivedKey,
		memoryKiB:   RequiredMemory,
		parallelism: Threads,
		iterations:  Time,
	}), nil
	/*
		if utf8.RuneCountInString(password) > MaxLength {
			return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
		}
		passwordHash := sha256.Sum256([]byte(password))
		return hex.EncodeToString(passwordHash[:]), nil
	*/

}

func Verify(password, encodedHash string) bool {
	// Argon2id verify
	if strings.HasPrefix(encodedHash, "$argon2id$") {
		parsedHash, ok := parseArgon2idHash(encodedHash)
		if !ok || parsedHash.version != argon2.Version {
			return false
		}
		candidateKey := argon2.IDKey([]byte(password), parsedHash.salt, Time, RequiredMemory, Threads, KeyLen)
		return subtle.ConstantTimeCompare(parsedHash.derivedKey, candidateKey) == 1
	}

	// SHA256 Verify
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	expectedHash, ok := decodeLegacyHash(encodedHash)
	if !ok {
		return false
	}
	candidateHash := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
}

func NeedsRehash(encodedHash string) bool {
	if !strings.HasPrefix(encodedHash, "$argon2id$") {
		return true
	}

	parsedHash, ok := parseArgon2idHash(encodedHash)
	if !ok || parsedHash.version != argon2.Version {
		return true
	}
	if parsedHash.memoryKiB != RequiredMemory || parsedHash.parallelism != Threads || parsedHash.iterations != Time || len(parsedHash.derivedKey) != KeyLen {
		return true
	}
	return false
}
