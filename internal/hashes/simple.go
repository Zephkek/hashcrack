package hashes

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"sync"
	sha256simd "github.com/minio/sha256-simd"
	md5simd "github.com/minio/md5-simd"
	"golang.org/x/crypto/sha3"
)

type simpleHasher struct { algo string }

func (s simpleHasher) Name() string { return s.algo }

var (
	md5Once sync.Once
	md5Srv md5simd.Server
)

func getMD5Server() md5simd.Server {
	md5Once.Do(func(){ md5Srv = md5simd.NewServer() })
	return md5Srv
}

// DigestMany implements BatchByteDigester for md5 and sha256.
func (s simpleHasher) DigestMany(plains [][]byte, p Params) ([][]byte, error) {
	switch s.algo {
	case "md5":
		srv := getMD5Server()
	// Create N hashers and feed; md5-simd server parallelizes lanes internally.
		out := make([][]byte, len(plains))
		hs := make([]md5simd.Hasher, len(plains))
		for i := range hs { hs[i] = srv.NewHash() }
		for i, h := range hs {
			_, _ = h.Write(plains[i])
			if len(p.Salt) > 0 { _, _ = h.Write(p.Salt) }
		}
		for i, h := range hs { out[i] = h.Sum(nil); h.Close() }
		return out, nil
	case "sha256":
		// Use sha256-simd Sum256 per input; there is no explicit server API exposed, but Sum256 is fast.
		out := make([][]byte, len(plains))
		for i, b := range plains {
			bb := append(append([]byte(nil), b...), p.Salt...)
			v := sha256simd.Sum256(bb)
			out[i] = v[:]
		}
		return out, nil
	default:
		// Fallback: single hashing
		out := make([][]byte, len(plains))
		for i, b := range plains {
			d, _ := s.DigestBytes(b, p)
			out[i] = d
		}
		return out, nil
	}
}

// DigestBytes implements ByteDigester for simple hash algorithms that produce
// fixed-size digests and are typically hex-encoded in textual form. This avoids
// the hex encoding and string allocations on hot paths.
func (s simpleHasher) DigestBytes(plain []byte, p Params) ([]byte, error) {
	switch s.algo {
	case "md5":
		if cap(plain) >= len(plain)+len(p.Salt) {
			plain = plain[:len(plain)+len(p.Salt)]
			copy(plain[len(plain)-len(p.Salt):], p.Salt)
		} else {
			plain = append(append([]byte(nil), plain...), p.Salt...)
		}
		// For tiny messages, stdlib md5 is faster than md5-simd setup overhead.
		if len(plain) < 64 {
			v := md5.Sum(plain)
			return v[:], nil
		}
		h := getMD5Server().NewHash(); defer h.Close()
		_, _ = h.Write(plain)
		return h.Sum(nil), nil
	case "sha1":
		if cap(plain) >= len(plain)+len(p.Salt) {
			plain = plain[:len(plain)+len(p.Salt)]
			copy(plain[len(plain)-len(p.Salt):], p.Salt)
		} else {
			plain = append(append([]byte(nil), plain...), p.Salt...)
		}
		v := sha1.Sum(plain)
		return v[:], nil
	case "sha256":
		if cap(plain) >= len(plain)+len(p.Salt) {
			plain = plain[:len(plain)+len(p.Salt)]
			copy(plain[len(plain)-len(p.Salt):], p.Salt)
		} else {
			plain = append(append([]byte(nil), plain...), p.Salt...)
		}
		v := sha256simd.Sum256(plain)
		return v[:], nil
	case "sha384":
		if cap(plain) >= len(plain)+len(p.Salt) {
			plain = plain[:len(plain)+len(p.Salt)]
			copy(plain[len(plain)-len(p.Salt):], p.Salt)
		} else {
			plain = append(append([]byte(nil), plain...), p.Salt...)
		}
		v := sha512.Sum384(plain)
		return v[:], nil
	case "sha512":
		if cap(plain) >= len(plain)+len(p.Salt) {
			plain = plain[:len(plain)+len(p.Salt)]
			copy(plain[len(plain)-len(p.Salt):], p.Salt)
		} else {
			plain = append(append([]byte(nil), plain...), p.Salt...)
		}
		v := sha512.Sum512(plain)
		return v[:], nil
	case "sha3-224":
		h := sha3.New224()
		_, _ = h.Write(plain)
		if len(p.Salt) > 0 { _, _ = h.Write(p.Salt) }
		return h.Sum(nil), nil
	case "sha3-256":
		h := sha3.New256()
		_, _ = h.Write(plain)
		if len(p.Salt) > 0 { _, _ = h.Write(p.Salt) }
		return h.Sum(nil), nil
	case "sha3-384":
		h := sha3.New384()
		_, _ = h.Write(plain)
		if len(p.Salt) > 0 { _, _ = h.Write(p.Salt) }
		return h.Sum(nil), nil
	case "sha3-512":
		h := sha3.New512()
		_, _ = h.Write(plain)
		if len(p.Salt) > 0 { _, _ = h.Write(p.Salt) }
		return h.Sum(nil), nil
	case "shake128":
		h := sha3.NewShake128()
		_, _ = h.Write(plain)
		if len(p.Salt) > 0 { _, _ = h.Write(p.Salt) }
		out := make([]byte, 32) // 256-bit output for SHAKE128
		_, _ = h.Read(out)
		return out, nil
	case "shake256":
		h := sha3.NewShake256()
		_, _ = h.Write(plain)
		if len(p.Salt) > 0 { _, _ = h.Write(p.Salt) }
		out := make([]byte, 64) // 512-bit output for SHAKE256
		_, _ = h.Read(out)
		return out, nil
	default:
		return nil, nil
	}
}

func (s simpleHasher) hashBytes(b []byte) []byte {
	switch s.algo {
	case "md5":
		v := md5.Sum(b); return v[:]
	case "sha1":
		v := sha1.Sum(b)
		return v[:]
	case "sha256":
		v := sha256simd.Sum256(b)
		return v[:]
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
	// Fast path: if target is hex and algorithm supports digest bytes, avoid
	// building hex strings and compare bytes directly.
	if bd, ok := interface{}(s).(ByteDigester); ok {
		// Accept optional 0x prefix; case-insensitive
		t := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(target)), "0x")
		if tb, err := hex.DecodeString(t); err == nil {
			// Pass only plaintext; DigestBytes adds salt internally
			sum, _ := bd.DigestBytes([]byte(plain), p)
			if len(sum) != len(tb) { return false, nil }
			var v byte
			for i := 0; i < len(sum); i++ { v |= sum[i] ^ tb[i] }
			return v == 0, nil
		}
	}
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
