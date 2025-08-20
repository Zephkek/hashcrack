package hashes

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strings"
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
}
