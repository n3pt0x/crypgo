package encryption

import "encoding/binary"

// ChunkNonce fills nonce (the AEAD nonce size) for one chunk of a stream: the
// random prefix, cut to fit, then the chunk index (big-endian) and a final byte
// that is 1 only on the last chunk. Reordering, duplicating or dropping chunks
// therefore changes the nonce and fails authentication.
func ChunkNonce(nonce []byte, prefix []byte, index uint64, last bool) {
	counter := len(nonce) - NonceLastFlagSize - NonceCounterSize

	copy(nonce[:counter], prefix)
	binary.BigEndian.PutUint64(nonce[counter:], index)

	nonce[len(nonce)-1] = 0
	if last {
		nonce[len(nonce)-1] = 1
	}
}
