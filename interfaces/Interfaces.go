package interfaces

import "github.com/rawansuww/go-keyman/types"

type KeyManager interface {
	RegisterProvider(string, Provider)
	DeleteProvider(string)
	GetKeyByProviderId(string) types.Key
	RefreshKey(string) types.Key
	RefreshAllKeys() map[string]types.Key
}

type Provider interface {
	FetchKeyFromStore() (types.Key, types.InternalError)
	GetIdentifier() string
}
