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
