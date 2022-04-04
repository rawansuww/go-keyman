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
	// providers []interfaces.Provider
	// keys      map[string]types.Key
	kp map[string]keyProvider
}

func (keyman *keyManager) RegisterProvider(p interfaces.Provider) {
	keyman.providers = append(keyman.providers, p)
	key, err := p.FetchKeyFromStore()
	keyman.keys[p.GetIdentifier()] = key
	if err.Error() != "" {
		log.Println("Failed to register provider due to fetching")
	}
}

func (keyman *keyManager) GetKeyByProviderId(x string) types.Key {
	key := keyman.keys[x]
	return key
}

func (keyman *keyManager) DeleteProvider(p interfaces.Provider) {
	for i := 0; i < len(keyman.providers); i++ {
		if keyman.providers[i].GetIdentifier() == p.GetIdentifier() {
			keyman.providers = append(keyman.providers[:i], keyman.providers[i+1:]...)
			i--
			break
		} else {
			log.Println("Provider with this ID is not found!")

		}
	}
}

func (keyman *keyManager) RefreshAllKeys() map[string]types.Key {
	var wg sync.WaitGroup
	wg.Add(len(keyman.providers))
	for _, provider := range keyman.providers {
		go func(provider interfaces.Provider) {
			defer wg.Done()
			key, err := provider.FetchKeyFromStore()
			if err.Error() != "" {
				log.Println("Failed to refresh due to fetching")
			}
			keyman.keys[provider.GetIdentifier()] = key
		}(provider)
	}
	wg.Wait()
	return keyman.keys
}

func (keyman *keyManager) RefreshKeys(x string) types.Key {
	for i := 0; i < len(keyman.providers); i++ {
		if keyman.providers[i].GetIdentifier() == x {
			key, err := keyman.providers[i].FetchKeyFromStore()
			if err.Error() != "" {
				log.Println("Failed to refresh due to fetching")
			}
			keyman.keys[x] = key
			break
		} else {
			log.Println("Provider with this ID is not found!")

		}
	}
	return keyman.keys[x]

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
