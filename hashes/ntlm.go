package hashes

import (
	"encoding/hex"
	"unicode/utf16"
	"strings"

	"golang.org/x/crypto/md4"
)

type ntlmHasher struct{}

func (n ntlmHasher) Name() string { return "ntlm" }

func (n ntlmHasher) Hash(plain string, _ Params) (string, error) {
	//convert to UTF-16LE
	runes := []rune(plain)
	utf16s := utf16.Encode(runes)
	b := make([]byte, len(utf16s)*2)
	for i, v := range utf16s {
		b[i*2] = byte(v)
		b[i*2+1] = byte(v >> 8)
	}
	h := md4.New()
	_, _ = h.Write(b)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum), nil
}

func (n ntlmHasher) Compare(target string, plain string, p Params) (bool, error) {
	h, _ := n.Hash(plain, p)
	return strings.EqualFold(h, target), nil
}

func init() { Register(ntlmHasher{}) }
