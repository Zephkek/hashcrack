package cracker

import (
	"context"
	"testing"

	"edu/hashcrack/internal/hashes"
)

func TestWordlistMD5(t *testing.T) {
	h, err := hashes.Get("md5")
	if err != nil { t.Fatal(err) }
	c := New(Options{Workers: 2})
	defer c.Close()
	res, err := c.CrackWordlist(context.Background(), h, hashes.Params{}, "5f4dcc3b5aa765d61d8327deb882cf99", "../../testdata/rockyou-mini.txt")
	if err != nil { t.Fatal(err) }
	if !res.Found || res.Plaintext != "password" {
		t.Fatalf("expected password, got %+v", res)
	}
}
