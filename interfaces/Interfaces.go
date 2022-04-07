package interfaces

import "github.com/rawansuww/go-keyman/types"

type KeyManager interface {
	RegisterProvider(Provider)
	DeleteProvider(string)
	GetKeyByProviderId(string) types.Key
	RefreshKey(string)
	RefreshAllKeys()
}

type Provider interface {
	FetchKeyFromStore() (types.Key, types.InternalError)
	GetIdentifier() string
}
