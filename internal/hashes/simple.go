package hashes

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"golang.org/x/crypto/sha3"

	md5simd "github.com/minio/md5-simd"
	sha256simd "github.com/minio/sha256-simd"
	"sync"
)

type simpleHasher struct { algo string }

func (s simpleHasher) Name() string { return s.algo }

func (s simpleHasher) hashBytes(b []byte) []byte {
	switch s.algo {
	case "md5":
	// MD5
	v := md5.Sum(b); return v[:]
	case "sha1":
		v := sha1.Sum(b); return v[:]
	case "sha256":
	// sha256-simd
		v := sha256simd.Sum256(b); return v[:]
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
	// Decode target once to avoid extra hex work
	if th, ok := decodeTargetHex(target, s.algo); ok {
		buf := append([]byte(plain), p.Salt...)
		sum := s.hashBytes(buf)
		if len(sum) != len(th) { return false, nil }
		for i := range sum { if sum[i] != th[i] { return false, nil } }
		return true, nil
	}
	h, _ := s.Hash(plain, p)
	return strings.EqualFold(h, target), nil
}

// Byte-wise compare to avoid string allocations.
func (s simpleHasher) CompareBytes(target string, plain []byte, p Params) (bool, error) {
	if th, ok := decodeTargetHex(target, s.algo); ok {
		if len(p.Salt) > 0 {
			buf := make([]byte, 0, len(plain)+len(p.Salt))
			buf = append(buf, plain...)
			buf = append(buf, p.Salt...)
			sum := s.hashBytes(buf)
			if len(sum) != len(th) { return false, nil }
			for i := range sum { if sum[i] != th[i] { return false, nil } }
			return true, nil
		}
		sum := s.hashBytes(plain)
		if len(sum) != len(th) { return false, nil }
		for i := range sum { if sum[i] != th[i] { return false, nil } }
		return true, nil
	}
	// Hex fallback
	if len(p.Salt) > 0 {
		buf := make([]byte, 0, len(plain)+len(p.Salt))
		buf = append(buf, plain...)
		buf = append(buf, p.Salt...)
		sum := s.hashBytes(buf)
		enc := make([]byte, hex.EncodedLen(len(sum)))
		hex.Encode(enc, sum)
		return strings.EqualFold(string(enc), target), nil
	}
	sum := s.hashBytes(plain)
	enc := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(enc, sum)
	return strings.EqualFold(string(enc), target), nil
}

// Batch compare against a hex target; returns index or -1.
func (s simpleHasher) CompareBatchHex(target string, batch [][]byte, p Params) (int, error) {
	if th, ok := decodeTargetHex(target, s.algo); ok {
		// Fast path on decoded bytes; MD5 uses md5-simd server
		if s.algo == "md5" {
			srv := getMD5Server()
			type md5Hasher interface{ Write([]byte) (int, error); Sum([]byte) []byte; Close() error }
			hs := make([]md5Hasher, len(batch))
			for i, b := range batch {
				h := srv.NewHash()
				if len(p.Salt) > 0 {
					buf := make([]byte, 0, len(b)+len(p.Salt))
					buf = append(buf, b...)
					buf = append(buf, p.Salt...)
					_, _ = h.Write(buf)
				} else {
					_, _ = h.Write(b)
				}
				hs[i] = h
			}
			for i, h := range hs {
				sum := h.Sum(nil)
				if len(sum) == len(th) {
					match := true
					for k := range sum { if sum[k] != th[k] { match = false; break } }
					if match { return i, nil }
				}
				h.Close()
			}
			return -1, nil
		}
		for i := range batch {
			var sum []byte
			if len(p.Salt) > 0 {
				buf := make([]byte, 0, len(batch[i])+len(p.Salt))
				buf = append(buf, batch[i]...)
				buf = append(buf, p.Salt...)
				sum = s.hashBytes(buf)
			} else {
				sum = s.hashBytes(batch[i])
			}
			if len(sum) != len(th) { continue }
			eq := true
			for k := range sum { if sum[k] != th[k] { eq = false; break } }
			if eq { return i, nil }
		}
		return -1, nil
	}
	// Fallback: hex-encode path
	targetLower := strings.ToLower(target)
	for i := range batch {
		var sum []byte
		if len(p.Salt) > 0 {
			buf := make([]byte, 0, len(batch[i])+len(p.Salt))
			buf = append(buf, batch[i]...)
			buf = append(buf, p.Salt...)
			sum = s.hashBytes(buf)
		} else {
			sum = s.hashBytes(batch[i])
		}
		enc := make([]byte, hex.EncodedLen(len(sum)))
		hex.Encode(enc, sum)
		if strings.EqualFold(string(enc), targetLower) { return i, nil }
	}
	return -1, nil
}

// Decode hex target based on expected algo length.
func decodeTargetHex(target, algo string) ([]byte, bool) {
	want := hashLen(algo)
	if want == 0 || len(target) != want*2 { return nil, false }
	out := make([]byte, want)
	if _, err := hex.Decode(out, []byte(strings.ToLower(target))); err != nil { return nil, false }
	return out, true
}

func hashLen(algo string) int {
	switch algo {
	case "md5":
		return 16
	case "sha1":
		return 20
	case "sha256":
		return 32
	case "sha384":
		return 48
	case "sha512":
		return 64
	case "sha3-224":
		return 28
	case "sha3-256":
		return 32
	case "sha3-384":
		return 48
	case "sha3-512":
		return 64
	case "shake128":
		return 32
	case "shake256":
		return 64
	default:
		return 0
	}
}

var (
	md5Once   sync.Once
	md5Server *md5simd.Server
)

func getMD5Server() *md5simd.Server {
	md5Once.Do(func() {
		srv := md5simd.NewServer()
		md5Server = &srv
	})
	return md5Server
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
