package encryption

import "runtime"

// ZeroBytes overwrites b with zeros once a secret is no longer needed.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
