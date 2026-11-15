package encryption

// ZeroBytes overwrites b with zeros once a secret is no longer needed.
func ZeroBytes(b []byte) {
	clear(b)
}
