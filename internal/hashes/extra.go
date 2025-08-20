package hashes

import (
	"crypto/md5"
	"crypto/des"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	ripemd160pkg "golang.org/x/crypto/ripemd160"
	"golang.org/x/text/encoding/charmap"
)

// RIPEMD-160 algorithm
type ripemd160 struct{}
func (r ripemd160) Name() string { return "ripemd160" }
func (r ripemd160) Hash(plain string, p Params) (string, error) {
	h := ripemd160pkg.New()
	h.Write(append([]byte(plain), p.Salt...))
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (r ripemd160) Compare(target, plain string, p Params) (bool, error) { h, _ := r.Hash(plain, p); return strings.EqualFold(h, target), nil }

// LM Hash (Microsoft LAN Manager)
// this is DES based and im still trying to understand how it works but from what i understand right now the algorithm goes by 6 steps:
// 1) Uppercase the password using Unicode case-folding
// 2) Convert to OEM code page bytes (historically CP850 on most systems) 
// 3) Pad/truncate to 14 bytes with 0x00 
// 4) Split into two 7-byte blocks; expand each to 8-byte DES keys with parity bits
// 5) DES-ECB encrypt the magic constant "KGS!@#$%" with each key and concatenate
// 6) Return 16-byte result as UPPERCASE hex (32 chars) 
// Thanks to (https://github.com/neozeed/Microsoft_LAN_Manager_1.0_SDK)
type lm struct{}
func (l lm) Name() string { return "lm" }
func (l lm) Hash(plain string, _ Params) (string, error) {
	// 1) Uppercase
	up := strings.ToUpper(plain)
	// 2) Convert to OEM bytes using Code Page 850. The encoder substitutes
	// unrepresentable runes with '?' to match historical behavior.
	enc := charmap.CodePage850.NewEncoder()
	oem, _ := enc.Bytes([]byte(up))
	// 3) Pad/truncate to 14 bytes
	buf := make([]byte, 14)
	copy(buf, oem)
	// split into two 7-byte parts
	p1 := lmExpandKey(buf[0:7])
	p2 := lmExpandKey(buf[7:14])
	magic := []byte("KGS!@#$%")
	c1, _ := des.NewCipher(p1)
	c2, _ := des.NewCipher(p2)
	out := make([]byte, 16)
	c1.Encrypt(out[0:8], magic)
	c2.Encrypt(out[8:16], magic)
	return strings.ToUpper(hex.EncodeToString(out)), nil
}
func (l lm) Compare(target, plain string, p Params) (bool, error) {
	h, err := l.Hash(plain, p)
	if err != nil { return false, err }
	return strings.EqualFold(h, target), nil
}

// MySQL 4.1+ double SHA1, uppercase hex
type mysql41 struct{}
func (m mysql41) Name() string { return "mysql" }
func (m mysql41) Hash(plain string, _ Params) (string, error) {
	h1 := sha1.Sum([]byte(plain))
	h2 := sha1.Sum(h1[:])
	return "*" + strings.ToUpper(hex.EncodeToString(h2[:])), nil
}
func (m mysql41) Compare(target, plain string, p Params) (bool, error) { h, _ := m.Hash(plain, p); return strings.EqualFold(h, target), nil }

// Cisco Type 7 reversible encoding (inpsired from the Crackhash project)
type cisco7 struct{}
func (c cisco7) Name() string { return "cisco7" }
func (c cisco7) Hash(plain string, _ Params) (string, error) { return "", errors.New("cisco7 hashing not supported") }
func (c cisco7) Compare(target, plain string, _ Params) (bool, error) {
	dec, err := cisco7Decode(target)
	if err != nil { return false, err }
	return dec == plain, nil
}

// LDAP MD5 and SHA
type ldapMD5 struct{}
func (l ldapMD5) Name() string { return "ldap_md5" }
func (l ldapMD5) Hash(plain string, _ Params) (string, error) {
	sum := md5Bytes([]byte(plain))
	return "{MD5}" + base64.StdEncoding.EncodeToString(sum), nil
}
func (l ldapMD5) Compare(target, plain string, p Params) (bool, error) { h, _ := l.Hash(plain, p); return h == target, nil }

type ldapSHA1 struct{}
func (l ldapSHA1) Name() string { return "ldap_sha1" }
func (l ldapSHA1) Hash(plain string, _ Params) (string, error) {
	sum := sha1.Sum([]byte(plain))
	return "{SHA}" + base64.StdEncoding.EncodeToString(sum[:]), nil
}
func (l ldapSHA1) Compare(target, plain string, p Params) (bool, error) { h, _ := l.Hash(plain, p); return h == target, nil }

func init() {
	Register(ripemd160{})
	Register(mysql41 {})
	Register(cisco7 {})
	registry["cisco"] = cisco7{}
	Register(ldapMD5 {})
	Register(ldapSHA1 {})
	Register(lm {})
}

func md5Bytes(b []byte) []byte { h := md5.Sum(b); return h[:] }

// cisco7 decoder
func cisco7Decode(s string) (string, error) {
	xlat := []byte("dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87")
	if len(s) < 2 { return "", fmt.Errorf("invalid cisco7") }
	var seed int
	_, err := fmt.Sscanf(s[:2], "%02d", &seed)
	if err != nil { return "", err }
	data := s[2:]
	if len(data)%2 != 0 { return "", fmt.Errorf("invalid hex length") }
	out := make([]byte, len(data)/2)
	for i := 0; i < len(out); i++ {
		var v byte
		_, err := fmt.Sscanf(data[i*2:i*2+2], "%02X", &v)
		if err != nil { return "", err }
		out[i] = v ^ xlat[(seed+i)%len(xlat)]
	}
	return string(out), nil
}

// expand 7-byte into 8-byte DES key by inserting parity bits.... no salt yes
func lmExpandKey(b7 []byte) []byte {
	b := make([]byte, 8)
	b[0] = b7[0] & 0xFE
	b[1] = ((b7[0] << 7) | (b7[1] >> 1)) & 0xFE
	b[2] = ((b7[1] << 6) | (b7[2] >> 2)) & 0xFE
	b[3] = ((b7[2] << 5) | (b7[3] >> 3)) & 0xFE
	b[4] = ((b7[3] << 4) | (b7[4] >> 4)) & 0xFE
	b[5] = ((b7[4] << 3) | (b7[5] >> 5)) & 0xFE
	b[6] = ((b7[5] << 2) | (b7[6] >> 6)) & 0xFE
	b[7] = (b7[6] << 1) & 0xFE
	for i := 0; i < 8; i++ {
		b[i] |= byte(parity(b[i]))
	}
	return b
}

func parity(x byte) int {
	// odd parity bit (set LSB to make odd number of bits)
	x ^= x >> 4
	x ^= x >> 2
	x ^= x >> 1
	return int(^x) & 1
}
