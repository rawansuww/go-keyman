package interfaces

import "github.com/rawansuww/go-keyman/types"

type KeyManager interface {
	RegisterProvider(string, Provider)
	DeleteProvider(string)
	GetKeyByProviderId(string) types.Key
	RefreshKeys() error
}
