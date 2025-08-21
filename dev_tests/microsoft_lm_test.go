package hashes

import "testing"

// Test vectors from widely cited sources
// "PASSWORD" -> E52CAC67419A9A224A3B108F3FA6CB6D
// "PASSWORD.." ->  (second half), and "" (empty) -> AAD3B435B51404EEAAD3B435B51404EE
func TestLMHashVectors(t *testing.T) {
	h, _ := Get("lm")
	out, err := h.Hash("password", Params{})
	if err != nil { t.Fatalf("err: %v", err) }
	if out != "E52CAC67419A9A224A3B108F3FA6CB6D" {
		t.Fatalf("PASSWORD expected E52... got %s", out)
	}

	out2, err := h.Hash("", Params{})
	if err != nil { t.Fatalf("err: %v", err) }
	if out2 != "AAD3B435B51404EEAAD3B435B51404EE" {
		t.Fatalf("empty expected AAD3... got %s", out2)
	}
}
