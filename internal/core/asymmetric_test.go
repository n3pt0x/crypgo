package core_test

import (
	"bytes"
	"crypto/hpke"
	"errors"
	"testing"

	"github.com/n3pt0x/crypgo/internal/core"
	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
)

func newTestKey(t *testing.T) hpke.PrivateKey {
	t.Helper()

	priv, err := encryption.GenerateHybrid()
	if err != nil {
		t.Fatalf("GenerateHybrid has failed: %v", err)
	}

	return priv
}

// asymHeaderSize is the size of the header of a file encrypted for n recipients.
func asymHeaderSize(n int) int {
	return stanzaOffset + n*encryption.StanzaSize
}

func encryptAsym(t *testing.T, recipients []hpke.PublicKey, algo uint8, plaintext []byte, opts core.Options) []byte {
	t.Helper()

	var out bytes.Buffer
	if err := core.EncryptAsymmetric(bytes.NewReader(plaintext), &out, recipients, algo, opts); err != nil {
		t.Fatalf("EncryptAsymmetric has failed: %v", err)
	}

	return out.Bytes()
}

func decryptAsym(data []byte, priv hpke.PrivateKey, workers int) ([]byte, error) {
	r := bytes.NewReader(data)

	header, err := core.ReadHeader(r)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	err = core.DecryptAsymmetric(header, r, &out, priv, workers)

	return out.Bytes(), err
}

func TestAsymmetricRoundTrip(t *testing.T) {
	priv := newTestKey(t)

	algos := map[string]uint8{
		"aes-gcm":   format.AlgoAESGCM,
		"xchacha20": format.AlgoXChaCha20Poly1305,
	}

	for name, algo := range algos {
		t.Run(name, func(t *testing.T) {
			data := encryptAsym(t, []hpke.PublicKey{priv.PublicKey()}, algo, testMessage, core.Options{})

			plaintext, err := decryptAsym(data, priv, 1)
			if err != nil {
				t.Fatalf("DecryptAsymmetric has failed: %v", err)
			}
			if !bytes.Equal(plaintext, testMessage) {
				t.Fatalf("plaintext = %q, want %q", plaintext, testMessage)
			}
		})
	}
}

func TestAsymmetricRoundTripChunksAndWorkers(t *testing.T) {
	priv := newTestKey(t)
	message := bytes.Repeat(testMessage, 20) // 540 bytes, 17 chunks of 32 bytes

	data := encryptAsym(t, []hpke.PublicKey{priv.PublicKey()}, format.AlgoXChaCha20Poly1305, message, core.Options{Workers: 4, ChunkSize: 32})

	for _, workers := range []int{1, 4} {
		plaintext, err := decryptAsym(data, priv, workers)
		if err != nil {
			t.Fatalf("DecryptAsymmetric(workers=%d) has failed: %v", workers, err)
		}
		if !bytes.Equal(plaintext, message) {
			t.Fatalf("plaintext (workers=%d) differs from the message", workers)
		}
	}
}

func TestAsymmetricMultipleRecipients(t *testing.T) {
	a, b, c := newTestKey(t), newTestKey(t), newTestKey(t)

	data := encryptAsym(t, []hpke.PublicKey{a.PublicKey(), b.PublicKey()}, format.AlgoXChaCha20Poly1305, testMessage, core.Options{})

	if len(data) < asymHeaderSize(2) || data[stanzaCountOffset] != 2 {
		t.Fatalf("header does not hold 2 stanzas")
	}

	for name, priv := range map[string]hpke.PrivateKey{"first recipient": a, "second recipient": b} {
		plaintext, err := decryptAsym(data, priv, 1)
		if err != nil {
			t.Fatalf("%s: DecryptAsymmetric has failed: %v", name, err)
		}
		if !bytes.Equal(plaintext, testMessage) {
			t.Fatalf("%s: plaintext = %q, want %q", name, plaintext, testMessage)
		}
	}

	if _, err := decryptAsym(data, c, 1); !errors.Is(err, encryption.ErrWrongIdentity) {
		t.Fatalf("not a recipient: error = %v, want %v", err, encryption.ErrWrongIdentity)
	}
}

func TestEncryptAsymmetricRecipientCount(t *testing.T) {
	pub := newTestKey(t).PublicKey()

	tooMany := make([]hpke.PublicKey, format.MaxRecipients+1)
	for i := range tooMany {
		tooMany[i] = pub
	}

	for name, recipients := range map[string][]hpke.PublicKey{"none": nil, "too many": tooMany} {
		var out bytes.Buffer
		err := core.EncryptAsymmetric(bytes.NewReader(testMessage), &out, recipients, format.AlgoAESGCM, core.Options{})
		if !errors.Is(err, format.ErrInvalidStanzas) {
			t.Errorf("%s: error = %v, want %v", name, err, format.ErrInvalidStanzas)
		}
		if out.Len() != 0 {
			t.Errorf("%s: %d bytes were written despite the error", name, out.Len())
		}
	}
}

// Two encryptions never give the same stanza.
func TestEncryptAsymmetricStanzaIsFresh(t *testing.T) {
	recipients := []hpke.PublicKey{newTestKey(t).PublicKey()}
	end := asymHeaderSize(1)

	a := encryptAsym(t, recipients, format.AlgoAESGCM, testMessage, core.Options{})
	b := encryptAsym(t, recipients, format.AlgoAESGCM, testMessage, core.Options{})

	if bytes.Equal(a[stanzaOffset:end], b[stanzaOffset:end]) {
		t.Fatal("two encryptions produced the same stanza")
	}
}

func TestDecryptAsymmetricErrors(t *testing.T) {
	priv := newTestKey(t)
	other := newTestKey(t)
	valid := encryptAsym(t, []hpke.PublicKey{priv.PublicKey()}, format.AlgoAESGCM, testMessage, core.Options{})
	headerSize := asymHeaderSize(1)

	with := func(mutate func(b []byte)) []byte {
		b := bytes.Clone(valid)
		mutate(b)
		return b
	}

	tests := []struct {
		name string
		data []byte
		priv hpke.PrivateKey
		want error
	}{
		{"empty input", nil, priv, format.ErrTruncated},
		{"header only", valid[:headerSize], priv, format.ErrTruncated},
		{"bad magic", with(func(b []byte) { b[0] ^= 0xff }), priv, format.ErrInvalidMagic},
		{"no stanza", with(func(b []byte) { b[stanzaCountOffset] = 0 }), priv, format.ErrInvalidStanzas},
		{"too many stanzas", with(func(b []byte) { b[stanzaCountOffset] = format.MaxRecipients + 1 }), priv, format.ErrInvalidStanzas},
		{"wrong key", valid, other, encryption.ErrWrongIdentity},
		{"tampered ciphertext", with(func(b []byte) { b[len(b)-1] ^= 0xff }), priv, encryption.ErrWrongIdentity},
		{"truncated ciphertext", valid[:len(valid)-1], priv, encryption.ErrWrongIdentity},
		{"tampered commitment", with(func(b []byte) { b[commitmentOffset] ^= 0xff }), priv, encryption.ErrWrongIdentity},
		{"tampered stanza", with(func(b []byte) { b[headerSize-1] ^= 0x01 }), priv, encryption.ErrWrongIdentity},
		{"tampered stanza enc", with(func(b []byte) { b[stanzaOffset] ^= 0x01 }), priv, encryption.ErrWrongIdentity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := decryptAsym(tt.data, tt.priv, 1)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if len(plaintext) != 0 {
				t.Fatalf("plaintext = %q, want nothing on error", plaintext)
			}
		})
	}
}
