package hashes
// still WIP functions from the crypto go library to optimize the hot path



// ByteDigester computes the raw digest bytes for a plaintext represented
// as UTF-8 bytes (plain) under the provided parameters.
// The returned slice must be a fresh allocation or otherwise immutable to callers.
type ByteDigester interface {
    DigestBytes(plain []byte, p Params) ([]byte, error)
}

// RuneDigester computes the raw digest bytes for a plaintext represented
// as a rune slice (Unicode code points). Only the first 'length' runes are considered.
// Intended for algorithms like NTLM that operate on UTF-16 of runes.
type RuneDigester interface {
    DigestRunes(plain []rune, length int, p Params) ([]byte, error)
}

// BatchByteDigester computes digests for multiple plaintexts in one call.
// The returned slice aligns with the input order.
// Implementors may use SIMD servers to process lanes in parallel.
type BatchByteDigester interface {
    DigestMany(plains [][]byte, p Params) ([][]byte, error)
}

