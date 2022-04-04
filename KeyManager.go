package gokeyman

import (
	"log"
	"sync"

	"github.com/rawansuww/go-keyman/interfaces"
	"github.com/rawansuww/go-keyman/types"
)

type keyProvider struct {
	p interfaces.Provider
	k types.Key
}

type keyManager struct {
	kp map[string]keyProvider
}

func (keyman *keyManager) RegisterProvider(p interfaces.Provider) {
	key, err := p.FetchKeyFromStore()
	if err.Error() != "" {
		log.Println("Failed to register provider due to fetching")
	}
	keyman.kp[p.GetIdentifier()] = keyProvider{
		p: p,
		k: key,
	}
}

func (keyman *keyManager) GetKeyByProviderId(x string) types.Key {
	key := keyman.kp[x].k
	return key
}

func (keyman *keyManager) DeleteProvider(p interfaces.Provider) {
	delete(keyman.kp, p.GetIdentifier())
}

func (keyman *keyManager) RefreshAllKeys() map[string]keyProvider {
	var wg sync.WaitGroup
	wg.Add(len(keyman.kp))
	for x, keyProvider := range keyman.kp {
		go func() { //do i need the same copy of variable?
			defer wg.Done()
			key, err := keyProvider.p.FetchKeyFromStore()
			keyProvider.k = key
			keyman.kp[x] = keyProvider
			if err.Error() != "" {
				log.Println("Failed to refresh due to fetching")
			}
		}()
	}
	wg.Wait()
	return keyman.kp
}

func (keyman *keyManager) RefreshKey(x string) keyProvider {
	keyProv := keyman.kp[x]
	key, err := keyProv.p.FetchKeyFromStore()
	if err.Error() != "" {
		log.Println("Failed to refresh due to fetching")
		return keyProvider{}

	}
	keyProv.k = key
	return keyman.kp[x]

}

func NewKeyManager(pp []interfaces.Provider) *keyManager {
	keyman := new(keyManager)
	kp := make(map[string]keyProvider)
	keyman.kp = kp
	for _, provider := range pp {
		keyman.RegisterProvider(provider)
	}
	return keyman
}
