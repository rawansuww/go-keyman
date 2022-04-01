package interfaces

import "github.com/rawansuww/go-keyman/types"

type Provider interface {
	FetchKeyFromStore() (types.Key, types.InternalError)
	GetIdentifier() string
}
