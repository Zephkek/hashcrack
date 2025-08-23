package hashes

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
	"github.com/ddulesov/gogost/gost34112012256"
	"github.com/ddulesov/gogost/gost34112012512"
	"github.com/c0mm4nd/go-ripemd"
)

type specializedHasher struct { algo string }
func (h specializedHasher) Name() string { return h.algo }

func (h specializedHasher) Hash(plain string, p Params) (string, error) {
	result, err := h.hashBytes([]byte(plain), p)
	if err != nil { return "", err }
	return hex.EncodeToString(result), nil
}

func (h specializedHasher) Compare(target, plain string, p Params) (bool, error) {
	switch h.algo {
	case "bcrypt":
		return bcrypt.CompareHashAndPassword([]byte(target), []byte(plain)) == nil, nil
	case "bcrypt-hmac-sha256-pass":
		hmacHash := hmac.New(sha256.New, []byte(plain))
		hmacHash.Write([]byte(plain))
		return bcrypt.CompareHashAndPassword([]byte(target), hmacHash.Sum(nil)) == nil, nil
	case "bcrypt-md5-pass":
		md5Hash := md5.Sum([]byte(plain))
		return bcrypt.CompareHashAndPassword([]byte(target), md5Hash[:]) == nil, nil
	case "bcrypt-sha1-pass":
		sha1Hash := sha1.Sum([]byte(plain))
		return bcrypt.CompareHashAndPassword([]byte(target), sha1Hash[:]) == nil, nil
	case "bcrypt-sha256-pass":
		sha256Hash := sha256.Sum256([]byte(plain))
		return bcrypt.CompareHashAndPassword([]byte(target), sha256Hash[:]) == nil, nil
	case "bcrypt-sha512-pass":
		sha512Hash := sha512.Sum512([]byte(plain))
		return bcrypt.CompareHashAndPassword([]byte(target), sha512Hash[:]) == nil, nil
	default:
		hash, err := h.Hash(plain, p)
		if err != nil { return false, err }
		return strings.EqualFold(hash, target), nil
	}
}

func (h specializedHasher) hashBytes(plain []byte, p Params) ([]byte, error) {
	switch h.algo {
	case "md5-salt-md5-pass-salt":
		inner := md5.Sum(plain)
		combined := append(p.Salt, inner[:]...)
		combined = append(combined, p.Salt...)
		outer := md5.Sum(combined)
		return outer[:], nil
	case "md5-md5-pass-md5-salt":
		inner1 := md5.Sum(plain)
		inner2 := md5.Sum(p.Salt)
		combined := append(inner1[:], inner2[:]...)
		outer := md5.Sum(combined)
		return outer[:], nil
	case "md5-md5-md5-pass":
		first := md5.Sum(plain)
		second := md5.Sum(first[:])
		third := md5.Sum(second[:])
		return third[:], nil
	case "md5-md5-md5-pass-salt":
		first := md5.Sum(plain)
		second := md5.Sum(first[:])
		third := md5.Sum(second[:])
		combined := append(third[:], p.Salt...)
		final := md5.Sum(combined)
		return final[:], nil
	case "md5-md5-md5-pass-salt1-salt2":
		first := md5.Sum(plain)
		second := md5.Sum(first[:])
		combined := append(second[:], p.Salt...)
		if len(p.Salt) > 16 {
			combined = append(combined, p.Salt[16:]...)
		}
		final := md5.Sum(combined)
		return final[:], nil
	case "md5-sha1-pass-salt":
		sha1Hash := sha1.Sum(plain)
		combined := append(sha1Hash[:], p.Salt...)
		md5Hash := md5.Sum(combined)
		return md5Hash[:], nil
	case "md5-sha1-pass-md5-pass-sha1-pass":
		sha1Hash := sha1.Sum(plain)
		md5Hash := md5.Sum(plain)
		combined := append(sha1Hash[:], md5Hash[:]...)
		combined = append(combined, sha1Hash[:]...)
		final := md5.Sum(combined)
		return final[:], nil
	case "md5-sha1-salt-md5-pass":
		md5Hash := md5.Sum(plain)
		sha1Hash := sha1.Sum(append(p.Salt, md5Hash[:]...))
		final := md5.Sum(sha1Hash[:])
		return final[:], nil
	case "md5-sha1-salt-pass":
		sha1Hash := sha1.Sum(append(p.Salt, plain...))
		md5Hash := md5.Sum(sha1Hash[:])
		return md5Hash[:], nil
	case "md5-sha1-md5-pass":
		md5Hash := md5.Sum(plain)
		sha1Hash := sha1.Sum(md5Hash[:])
		final := md5.Sum(sha1Hash[:])
		return final[:], nil
	case "md5-strtoupper-md5-pass":
		md5Hash := md5.Sum(plain)
		upperHex := strings.ToUpper(hex.EncodeToString(md5Hash[:]))
		final := md5.Sum([]byte(upperHex))
		return final[:], nil
	case "md5-utf16le-pass-salt":
		utf16Data := h.toUTF16LE(string(plain))
		combined := append(utf16Data, p.Salt...)
		hash := md5.Sum(combined)
		return hash[:], nil
	case "sha1-salt-pass-salt":
		combined := append(p.Salt, plain...)
		combined = append(combined, p.Salt...)
		hash := sha1.Sum(combined)
		return hash[:], nil
	case "sha1-salt-sha1-pass":
		sha1Hash := sha1.Sum(plain)
		combined := append(p.Salt, sha1Hash[:]...)
		final := sha1.Sum(combined)
		return final[:], nil
	case "sha1-salt-sha1-pass-salt":
		sha1Hash := sha1.Sum(append(plain, p.Salt...))
		combined := append(p.Salt, sha1Hash[:]...)
		final := sha1.Sum(combined)
		return final[:], nil
	case "sha1-salt-sha1-utf16le-username-utf16le-pass":
		userBytes := h.toUTF16LE("user")
		passBytes := h.toUTF16LE(string(plain))
		combined := append(userBytes, []byte(":")...)
		combined = append(combined, passBytes...)
		sha1Hash := sha1.Sum(combined)
		final := sha1.Sum(append(p.Salt, sha1Hash[:]...))
		return final[:], nil
	case "sha1-salt-utf16le-pass":
		utf16Data := h.toUTF16LE(string(plain))
		combined := append(p.Salt, utf16Data...)
		hash := sha1.Sum(combined)
		return hash[:], nil
	case "sha1-salt1-pass-salt2":
		salt1 := p.Salt
		salt2 := p.Salt
		if len(p.Salt) > 16 {
			salt2 = p.Salt[16:]
			salt1 = p.Salt[:16]
		}
		combined := append(salt1, plain...)
		combined = append(combined, salt2...)
		hash := sha1.Sum(combined)
		return hash[:], nil
	case "sha1-cx":
		return h.sha1CX(plain), nil
	case "sha1-md5-pass":
		md5Hash := md5.Sum(plain)
		sha1Hash := sha1.Sum(md5Hash[:])
		return sha1Hash[:], nil
	case "sha1-md5-pass-salt":
		md5Hash := md5.Sum(plain)
		combined := append(md5Hash[:], p.Salt...)
		sha1Hash := sha1.Sum(combined)
		return sha1Hash[:], nil
	case "sha1-md5-md5-pass":
		first := md5.Sum(plain)
		second := md5.Sum(first[:])
		sha1Hash := sha1.Sum(second[:])
		return sha1Hash[:], nil
	case "sha1-sha1-pass":
		first := sha1.Sum(plain)
		second := sha1.Sum(first[:])
		return second[:], nil
	case "sha1-sha1-pass-salt":
		first := sha1.Sum(plain)
		combined := append(first[:], p.Salt...)
		second := sha1.Sum(combined)
		return second[:], nil
	case "sha1-sha1-salt-pass-salt":
		combined := append(p.Salt, plain...)
		combined = append(combined, p.Salt...)
		first := sha1.Sum(combined)
		second := sha1.Sum(first[:])
		return second[:], nil
	case "sha1-utf16le-pass-salt":
		utf16Data := h.toUTF16LE(string(plain))
		combined := append(utf16Data, p.Salt...)
		hash := sha1.Sum(combined)
		return hash[:], nil
	case "sha224-pass-salt":
		hash := sha256.New224()
		hash.Write(plain)
		hash.Write(p.Salt)
		return hash.Sum(nil), nil
	case "sha224-salt-pass":
		hash := sha256.New224()
		hash.Write(p.Salt)
		hash.Write(plain)
		return hash.Sum(nil), nil
	case "sha224-sha1-pass":
		sha1Hash := sha1.Sum(plain)
		sha224Hash := sha256.Sum224(sha1Hash[:])
		return sha224Hash[:], nil
	case "sha224-sha224-pass":
		first := sha256.Sum224(plain)
		second := sha256.Sum224(first[:])
		return second[:], nil
	case "sha256-salt-pass-salt":
		combined := append(p.Salt, plain...)
		combined = append(combined, p.Salt...)
		hash := sha256.Sum256(combined)
		return hash[:], nil
	case "sha256-salt-sha256-pass":
		sha256Hash := sha256.Sum256(plain)
		combined := append(p.Salt, sha256Hash[:]...)
		final := sha256.Sum256(combined)
		return final[:], nil
	case "sha256-salt-sha256-bin-pass":
		sha256Hash := sha256.Sum256(plain)
		combined := append(p.Salt, sha256Hash[:]...)
		final := sha256.Sum256(combined)
		return final[:], nil
	case "sha256-salt-utf16le-pass":
		utf16Data := h.toUTF16LE(string(plain))
		combined := append(p.Salt, utf16Data...)
		hash := sha256.Sum256(combined)
		return hash[:], nil
	case "sha256-sha256-pass-salt":
		first := sha256.Sum256(plain)
		combined := append(first[:], p.Salt...)
		second := sha256.Sum256(combined)
		return second[:], nil
	case "sha256-sha256-bin-pass":
		first := sha256.Sum256(plain)
		second := sha256.Sum256(first[:])
		return second[:], nil
	case "sha256-utf16le-pass-salt":
		utf16Data := h.toUTF16LE(string(plain))
		combined := append(utf16Data, p.Salt...)
		hash := sha256.Sum256(combined)
		return hash[:], nil
	case "sha384-salt-pass":
		hash := sha512.New384()
		hash.Write(p.Salt)
		hash.Write(plain)
		return hash.Sum(nil), nil
	case "sha384-salt-utf16le-pass":
		utf16Data := h.toUTF16LE(string(plain))
		combined := append(p.Salt, utf16Data...)
		hash := sha512.Sum384(combined)
		return hash[:], nil
	case "sha384-utf16le-pass-salt":
		utf16Data := h.toUTF16LE(string(plain))
		combined := append(utf16Data, p.Salt...)
		hash := sha512.Sum384(combined)
		return hash[:], nil
	case "sha512-salt-utf16le-pass":
		utf16Data := h.toUTF16LE(string(plain))
		combined := append(p.Salt, utf16Data...)
		hash := sha512.Sum512(combined)
		return hash[:], nil
	case "sha512-sha512-pass-salt":
		first := sha512.Sum512(plain)
		combined := append(first[:], p.Salt...)
		second := sha512.Sum512(combined)
		return second[:], nil
	case "sha512-sha512-bin-pass-salt":
		first := sha512.Sum512(plain)
		combined := append(first[:], p.Salt...)
		second := sha512.Sum512(combined)
		return second[:], nil
	case "sha512-utf16le-pass-salt":
		utf16Data := h.toUTF16LE(string(plain))
		combined := append(utf16Data, p.Salt...)
		hash := sha512.Sum512(combined)
		return hash[:], nil
	case "hmac-ripemd160-pass":
		return h.hmacRipemd160(plain, plain), nil
	case "hmac-ripemd160-salt":
		return h.hmacRipemd160(p.Salt, plain), nil
	case "hmac-streebog-256-pass":
		return h.hmacStreebog256(plain, plain), nil
	case "hmac-streebog-256-salt":
		return h.hmacStreebog256(p.Salt, plain), nil
	case "hmac-streebog-512-pass":
		return h.hmacStreebog512(plain, plain), nil
	case "hmac-streebog-512-salt":
		return h.hmacStreebog512(p.Salt, plain), nil
	case "hmac-ripemd320-pass":
		return h.hmacRipemd320(plain, plain), nil
	case "hmac-ripemd320-salt":
		return h.hmacRipemd320(p.Salt, plain), nil
	case "pbkdf1-sha1":
		iter := 10000
		if p.PBKDF2Iterations > 0 { iter = p.PBKDF2Iterations }
		return pbkdf2.Key(plain, p.Salt, iter, 20, sha1.New), nil
	case "pbkdf2-hmac-md5":
		iter := 10000
		if p.PBKDF2Iterations > 0 { iter = p.PBKDF2Iterations }
		return pbkdf2.Key(plain, p.Salt, iter, 16, md5.New), nil
	case "pbkdf2-hmac-sha1":
		iter := 10000
		if p.PBKDF2Iterations > 0 { iter = p.PBKDF2Iterations }
		return pbkdf2.Key(plain, p.Salt, iter, 20, sha1.New), nil
	case "pbkdf2-hmac-sha256":
		iter := 10000
		if p.PBKDF2Iterations > 0 { iter = p.PBKDF2Iterations }
		return pbkdf2.Key(plain, p.Salt, iter, 32, sha256.New), nil
	case "pbkdf2-hmac-sha512":
		iter := 10000
		if p.PBKDF2Iterations > 0 { iter = p.PBKDF2Iterations }
		return pbkdf2.Key(plain, p.Salt, iter, 64, sha512.New), nil
	case "bcrypt":
		hash, err := bcrypt.GenerateFromPassword(plain, p.BcryptCost)
		return hash, err
	case "bcrypt-hmac-sha256-pass":
		hmacHash := hmac.New(sha256.New, plain)
		hmacHash.Write(plain)
		hash, err := bcrypt.GenerateFromPassword(hmacHash.Sum(nil), p.BcryptCost)
		return hash, err
	case "bcrypt-md5-pass":
		md5Hash := md5.Sum(plain)
		hash, err := bcrypt.GenerateFromPassword(md5Hash[:], p.BcryptCost)
		return hash, err
	case "bcrypt-sha1-pass":
		sha1Hash := sha1.Sum(plain)
		hash, err := bcrypt.GenerateFromPassword(sha1Hash[:], p.BcryptCost)
		return hash, err
	case "bcrypt-sha256-pass":
		sha256Hash := sha256.Sum256(plain)
		hash, err := bcrypt.GenerateFromPassword(sha256Hash[:], p.BcryptCost)
		return hash, err
	case "bcrypt-sha512-pass":
		sha512Hash := sha512.Sum512(plain)
		hash, err := bcrypt.GenerateFromPassword(sha512Hash[:], p.BcryptCost)
		return hash, err
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", h.algo)
	}
}

func (h specializedHasher) toUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	bytes := make([]byte, len(runes)*2)
	for i, r := range runes {
		bytes[i*2] = byte(r)
		bytes[i*2+1] = byte(r >> 8)
	}
	return bytes
}

func (h specializedHasher) sha1CX(plain []byte) []byte {
	hash := sha1.Sum(plain)
	result := make([]byte, 20)
	for i := 0; i < 20; i++ {
		result[i] = hash[i] ^ 0x5C
	}
	return result
}

func (h specializedHasher) hmacRipemd160(key, data []byte) []byte {
	hmacHash := hmac.New(ripemd160.New, key)
	hmacHash.Write(data)
	return hmacHash.Sum(nil)
}

func (h specializedHasher) hmacStreebog256(key, data []byte) []byte {
	hmacHash := hmac.New(gost34112012256.New, key)
	hmacHash.Write(data)
	return hmacHash.Sum(nil)
}

func (h specializedHasher) hmacStreebog512(key, data []byte) []byte {
	hmacHash := hmac.New(gost34112012512.New, key)
	hmacHash.Write(data)
	return hmacHash.Sum(nil)
}

func init() {
	algos := []string{
		"md5-salt-md5-pass-salt", "md5-md5-pass-md5-salt", "md5-md5-md5-pass",
		"md5-md5-md5-pass-salt", "md5-md5-md5-pass-salt1-salt2", "md5-sha1-pass-salt",
		"md5-sha1-pass-md5-pass-sha1-pass", "md5-sha1-pass-salt", "md5-sha1-salt-md5-pass",
		"md5-sha1-salt-pass", "md5-sha1-md5-pass", "md5-strtoupper-md5-pass",
		"md5-utf16le-pass-salt", "sha1-salt-pass-salt", "sha1-salt-sha1-pass",
		"sha1-salt-sha1-pass-salt", "sha1-salt-sha1-utf16le-username-utf16le-pass",
		"sha1-salt-utf16le-pass", "sha1-salt1-pass-salt2", "sha1-cx", "sha1-md5-pass",
		"sha1-md5-pass-salt", "sha1-md5-md5-pass", "sha1-sha1-pass",
		"sha1-sha1-pass-salt", "sha1-sha1-salt-pass-salt", "sha1-utf16le-pass-salt",
		"sha224-pass-salt", "sha224-salt-pass", "sha224-sha1-pass", "sha224-sha224-pass",
		"sha256-salt-pass-salt", "sha256-salt-sha256-pass", "sha256-salt-sha256-bin-pass",
		"sha256-salt-utf16le-pass", "sha256-sha256-pass-salt",
		"sha256-sha256-bin-pass", "sha256-utf16le-pass-salt", "sha384-salt-pass",
		"sha384-salt-utf16le-pass", "sha384-utf16le-pass-salt", "sha512-salt-utf16le-pass",
		"sha512-sha512-pass-salt", "sha512-sha512-bin-pass-salt", "sha512-utf16le-pass-salt",
		"hmac-ripemd160-pass", "hmac-ripemd160-salt",
		"hmac-streebog-256-pass", "hmac-streebog-256-salt", "hmac-streebog-512-pass", "hmac-streebog-512-salt",
		"hmac-ripemd320-pass", "hmac-ripemd320-salt",
		"pbkdf1-sha1", "pbkdf2-hmac-md5", "pbkdf2-hmac-sha1", "pbkdf2-hmac-sha256", "pbkdf2-hmac-sha512",
		"bcrypt", "bcrypt-hmac-sha256-pass", "bcrypt-md5-pass", "bcrypt-sha1-pass", "bcrypt-sha256-pass", "bcrypt-sha512-pass",
	}
	
	for _, algo := range algos {
		Register(specializedHasher{algo})
	}
}

func (h specializedHasher) hmacRipemd320(key, data []byte) []byte {
	hmacRipemd320 := hmac.New(ripemd.New320, key)
	hmacRipemd320.Write(data)
	return hmacRipemd320.Sum(nil)
}
