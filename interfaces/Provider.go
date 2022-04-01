package interfaces

type Provider interface {
	FetchKeyFromStore()
	GetIdentifier()
}
