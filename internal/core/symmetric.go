package core

import (
	"bytes"
	"encoding/binary"

	"github.com/n3pt0x/crypgo/internal/encryption"
	"github.com/n3pt0x/crypgo/internal/format"
	"github.com/n3pt0x/crypgo/internal/io"
)

func EncryptSymmetric(intput, output string, passphrase []byte, algo uint8) error {
	var salt []byte = encryption.GenerateSalt()
	var nonce, ciphertext []byte

	var derivedKey = encryption.DerivedKeyArgon2ID(passphrase, salt, encryption.KDFProfileArgon2idDefault)

	switch algo {
	case format.AlgoAESGCM:
		{
			var header format.HeaderAESGCM
			var file format.FileAESGCM
			var err error
			nonce = encryption.GenerateNonceAESGCM()
			ciphertext, err = encryption.EncryptAESGCM([]byte(intput), derivedKey, nonce)

			if err != nil {
				return err
			}

			header.Magic = format.MagicBytes
			header.Version = format.Version
			header.Mode = format.Symetric
			header.EncryptionAlgo = format.AlgoAESGCM
			header.KDFProfile = encryption.KDFProfileArgon2idDefault
			header.Salt = [16]byte(salt)
			header.Nonce = [12]byte(nonce)

			file.Header = header
			file.Ciphertext = ciphertext

			var buf bytes.Buffer

			err = header.IsValid()
			if err != nil {
				return err
			}

			binary.Write(&buf, binary.LittleEndian, file)

			err = io.AtomicWriteFile(output, []byte(buf))
			if err != nil {
				return err
			}
		}

	case format.AlgoXChaCha20Poly1305:
		{
			nonce = encryption.GenerateNonceXChaCha20Poly1305()
		}

	}

	return nil
}

func DecryptSymmetric(intput, output string, passphrase []byte, algo uint8) error

func VerifySymmetric(input string, passphrase []byte) error
