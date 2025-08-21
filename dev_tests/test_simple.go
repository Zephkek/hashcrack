package hashes

import "testing"

func TestSimpleHash(t *testing.T) {
	h, _ := Get("sha256")
	out, _ := h.Hash("abc", Params{})
	if out != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("unexpected: %s", out)
	}
}
