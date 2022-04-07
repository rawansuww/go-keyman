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
	if err != (types.InternalError{}) {
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

func (keyman *keyManager) DeleteProvider(x string) {
	delete(keyman.kp, x)
}

func (keyman *keyManager) RefreshAllKeys() {
	var wg sync.WaitGroup
	wg.Add(len(keyman.kp))
	for x, kp := range keyman.kp {
		go func(k *keyProvider, id string) {
			defer wg.Done()
			key, err := k.p.FetchKeyFromStore()
			k.k = key
			keyman.kp[id] = *k
			if err != (types.InternalError{}) {
				log.Println("Failed to refresh due to fetching")
			}
		}(&kp, x)
	}
	wg.Wait()

}

func (keyman *keyManager) RefreshKey(x string) {
	if len(keyman.kp) == 0 {
		log.Println("empty keymanager")

	}
	keyProv := keyman.kp[x]
	key, err := keyProv.p.FetchKeyFromStore()
	if err != (types.InternalError{}) {
		log.Println("Failed to refresh due to fetching")

	}
	keyProv.k = key
	if keyman.kp[x] == (keyProvider{}) {
		log.Println("error ")
	}

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
