package hashes

type ByteDigester interface {
    DigestBytes(plain []byte, p Params) ([]byte, error)
}

type RuneDigester interface {
    DigestRunes(plain []rune, length int, p Params) ([]byte, error)
}

type BatchByteDigester interface {
    DigestMany(plains [][]byte, p Params) ([][]byte, error)
}

