package types

type Key struct {
	PublicKey  []byte
	PrivateKey []byte
	Thumbprint []byte
	KeyId      []byte
}
