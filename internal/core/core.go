package core

import (
	"crypto/cipher"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

// Options are shared by every encryption mode.
type Options struct {
	Workers   int    // chunks processed in parallel, 1 when unset
	ChunkSize uint32 // plaintext bytes per chunk, format.DefaultChunkSize when unset
}

func newAEAD(algo uint8, key []byte) (cipher.AEAD, error) {
	switch algo {
	case format.AlgoAESGCM:
		return encryption.NewAESGCM(key)
	case format.AlgoXChaCha20Poly1305:
		return encryption.NewXChaCha20Poly1305(key)
	default:
		return nil, format.ErrInvalidAlgo
	}
}
