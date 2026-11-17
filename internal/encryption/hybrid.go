package encryption

import (
	"crypto/hpke"
	"fmt"
)

const (
	HybridPublicKeySize = 1216
	StanzaSize          = 1168
	hybridKeyInfo       = "crypgo v1 stanza"
)

func GenerateHybrid() (hpke.PrivateKey, error) {
	return hpke.MLKEM768X25519().GenerateKey()
}

func ParseHybridPrivate(seed []byte) (hpke.PrivateKey, error) {
	return hpke.MLKEM768X25519().NewPrivateKey(seed)
}

func ParseHybridPublic(b []byte) (hpke.PublicKey, error) {
	return hpke.MLKEM768X25519().NewPublicKey(b)
}

// WrapFileKey seals fileKey for pk.
func WrapFileKey(pk hpke.PublicKey, fileKey []byte) ([]byte, error) {
	if len(fileKey) != KeySize {
		return nil, fmt.Errorf("file key: got %d bytes, want %d", len(fileKey), KeySize)
	}

	stanza, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(hybridKeyInfo), fileKey)
	if err != nil {
		return nil, err
	}

	if len(stanza) != StanzaSize {
		return nil, fmt.Errorf("stanza: got %d bytes, want %d", len(stanza), StanzaSize)
	}

	return stanza, nil
}

func UnwrapFileKey(sk hpke.PrivateKey, stanza []byte) ([]byte, error) {
	if len(stanza) != StanzaSize {
		return nil, fmt.Errorf("stanza: got %d bytes, want %d", len(stanza), StanzaSize)
	}

	fileKey, err := hpke.Open(sk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(hybridKeyInfo), stanza)
	if err != nil {
		return nil, ErrWrongIdentity
	}

	return fileKey, nil
}
