package hashes

import (
	"fmt"
	"sort"
)

type Params struct {
	Salt []byte
	BcryptCost int
	ScryptN int
	ScryptR int
	ScryptP int
	ArgonTime uint32
	ArgonMemoryKB uint32
	ArgonParallelism uint8
	PBKDF2Iterations int
}

type Hasher interface {
	Name() string
	Hash(plain string, p Params) (string, error)
	Compare(target string, plain string, p Params) (bool, error)
}

// ByteComparer is an optional fast-path to avoid string allocations in hot loops.
// If implemented by a Hasher, callers may pass a UTF-8 plaintext as bytes.
type ByteComparer interface {
	CompareBytes(target string, plain []byte, p Params) (bool, error)
}

// BatchByteComparer allows comparing a batch of plaintexts at once against a single target.
// Returns the index within batch of a matching plaintext or -1 if none matched.
// Implementations should treat 'target' as the same format expected by Compare (e.g., hex for simple hashes).
type BatchByteComparer interface {
	CompareBatchHex(target string, batch [][]byte, p Params) (int, error)
}

var registry = map[string]Hasher{}

func Register(h Hasher) { registry[h.Name()] = h }

func Get(name string) (Hasher, error) {
	if h, ok := registry[name]; ok {
		return h, nil
	}
	return nil, fmt.Errorf("unknown algorithm: %s", name)
}

func List() []string {
	out := make([]string, 0, len(registry))
	for k := range registry { out = append(out, k) }
	sort.Strings(out)
	return out
}
