package hash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	timeCost    = 1
	memoryCost  = 64 * 1024
	parallelism = 4
	hashLength  = 32
	saltLength  = 16
)

// argon2 hash
func HashPassword(password string) string {
	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		log.Fatalf("Error generating random salt: %v", err)
	}

	hashed := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, parallelism, hashLength)
	return fmt.Sprintf("%x$%x", salt, hashed)
}

func VerifyPassword(storedPassword, providedPassword string) bool {
	parts := strings.Split(storedPassword, "$")
	if len(parts) != 2 {
		log.Fatal("Invalid stored password format")
		return false
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		log.Fatalf("Error decoding salt: %v", err)
		return false
	}
	storedHash, err := hex.DecodeString(parts[1])
	if err != nil {
		log.Fatalf("Error decoding hash: %v", err)
		return false
	}

	providedHash := argon2.IDKey([]byte(providedPassword), salt, timeCost, memoryCost, parallelism, hashLength)
	return subtle.ConstantTimeCompare(storedHash, providedHash) == 1
}
