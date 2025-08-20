package hashes

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

type kdfHasher struct { algo string }

func (k kdfHasher) Name() string { return k.algo }

func (k kdfHasher) Hash(plain string, p Params) (string, error) {
	switch k.algo {
	case "bcrypt":
		cost := bcrypt.DefaultCost
		if p.BcryptCost >= 4 && p.BcryptCost <= 31 { cost = p.BcryptCost }
		b, err := bcrypt.GenerateFromPassword([]byte(plain), cost)
		return string(b), err
	case "scrypt":
		salt := p.Salt
		if len(salt) == 0 { salt = make([]byte, 16); _, _ = rand.Read(salt) }
		N := 1<<15; r := 8; P := 1
		if p.ScryptN > 0 { N = p.ScryptN }
		if p.ScryptR > 0 { r = p.ScryptR }
		if p.ScryptP > 0 { P = p.ScryptP }
		b, err := scrypt.Key([]byte(plain), salt, N, r, P, 32)
		if err != nil { return "", err }
		return "scrypt:" + hex.EncodeToString(salt) + ":" + hex.EncodeToString(b), nil
	case "argon2id":
		salt := p.Salt
		if len(salt) == 0 { salt = make([]byte, 16); _, _ = rand.Read(salt) }
		t := uint32(1); mem := uint32(64*1024); par := uint8(4)
		if p.ArgonTime > 0 { t = p.ArgonTime }
		if p.ArgonMemoryKB > 0 { mem = p.ArgonMemoryKB }
		if p.ArgonParallelism > 0 { par = p.ArgonParallelism }
		b := argon2.IDKey([]byte(plain), salt, t, mem, uint8(par), 32)
		return "argon2id:" + hex.EncodeToString(salt) + ":" + hex.EncodeToString(b), nil
	default:
		return "", errors.New("unsupported kdf")
	}
}

func (k kdfHasher) Compare(target string, plain string, p Params) (bool, error) {
	switch k.algo {
	case "bcrypt":
		return bcrypt.CompareHashAndPassword([]byte(target), []byte(plain)) == nil, nil
	case "scrypt":
		// target format: scrypt:<saltHex>:<keyHex>
		saltHex, keyHex, err := split3(target, "scrypt")
		if err != nil { return false, err }
		salt, _ := hex.DecodeString(saltHex)
		key, _ := hex.DecodeString(keyHex)
		b, err := scrypt.Key([]byte(plain), salt, 1<<15, 8, 1, len(key))
		if err != nil { return false, err }
		return hex.EncodeToString(b) == hex.EncodeToString(key), nil
	case "argon2id":
		saltHex, keyHex, err := split3(target, "argon2id")
		if err != nil { return false, err }
		salt, _ := hex.DecodeString(saltHex)
		key, _ := hex.DecodeString(keyHex)
		b := argon2.IDKey([]byte(plain), salt, 1, 64*1024, 4, uint32(len(key)))
		return hex.EncodeToString(b) == hex.EncodeToString(key), nil
	default:
		return false, errors.New("unsupported kdf compare")
	}
}

func init() {
	Register(kdfHasher{"bcrypt"})
	Register(kdfHasher{"scrypt"})
	Register(kdfHasher{"argon2id"})
}

// split3 parses "prefix:salt:key" and validates the prefix
func split3(s, wantPrefix string) (salt, key string, err error) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 { return "", "", fmt.Errorf("invalid format for %s", wantPrefix) }
	if parts[0] != wantPrefix { return "", "", fmt.Errorf("invalid prefix: %s", parts[0]) }
	return parts[1], parts[2], nil
}
