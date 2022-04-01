package keymanager

import (
	"github.com/rawansuww/go-keyman/interfaces"
	"github.com/rawansuww/go-keyman/types"
)

type keyManager struct {
	providers []interfaces.Provider
	keys      map[string]types.Key
}

func (keyman *keyManager) GetKeyByProviderId(x string, p interfaces.Provider) {

}
func (keyman *keyManager) RegisterProvider(x string, p interfaces.Provider) {

}

func (keyman *keyManager) DeleteProvider(p interfaces.Provider) []byte {
}
