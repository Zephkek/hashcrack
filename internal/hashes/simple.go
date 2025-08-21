package hashes

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"golang.org/x/crypto/sha3"
)

type simpleHasher struct { algo string }

func (s simpleHasher) Name() string { return s.algo }

func (s simpleHasher) hashBytes(b []byte) []byte {
	switch s.algo {
	case "md5":
		v := md5.Sum(b); return v[:]
	case "sha1":
		v := sha1.Sum(b); return v[:]
	case "sha256":
		v := sha256.Sum256(b); return v[:]
	case "sha384":
		v := sha512.Sum384(b); return v[:]
	case "sha512":
		v := sha512.Sum512(b); return v[:]
	case "sha3-224":
		v := sha3.Sum224(b); return v[:]
	case "sha3-256":
		v := sha3.Sum256(b); return v[:]
	case "sha3-384":
		v := sha3.Sum384(b); return v[:]
	case "sha3-512":
		v := sha3.Sum512(b); return v[:]
	case "shake128":
		h := sha3.NewShake128()
		h.Write(b)
		out := make([]byte, 32) // 256-bit output for SHAKE128
		h.Read(out)
		return out
	case "shake256":
		h := sha3.NewShake256()
		h.Write(b)
		out := make([]byte, 64) // 512-bit output for SHAKE256
		h.Read(out)
		return out
	default:
		return nil
	}
}

func (s simpleHasher) Hash(plain string, p Params) (string, error) {
	buf := append([]byte(plain), p.Salt...)
	return hex.EncodeToString(s.hashBytes(buf)), nil
}

func (s simpleHasher) Compare(target string, plain string, p Params) (bool, error) {
	h, _ := s.Hash(plain, p)
	return strings.EqualFold(h, target), nil
}

func init() {
	Register(simpleHasher{"md5"})
	Register(simpleHasher{"sha1"})
	Register(simpleHasher{"sha256"})
	Register(simpleHasher{"sha384"})
	Register(simpleHasher{"sha512"})
	Register(simpleHasher{"sha3-224"})
	Register(simpleHasher{"sha3-256"})
	Register(simpleHasher{"sha3-384"})
	Register(simpleHasher{"sha3-512"})
	Register(simpleHasher{"shake128"})
	Register(simpleHasher{"shake256"})
}
