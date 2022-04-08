package gokeyman

import (
	"crypto/rsa"
	"log"
	"math/big"
	"testing"

	"github.com/rawansuww/go-keyman/interfaces"
	"github.com/rawansuww/go-keyman/types"
)

var p []interfaces.Provider
var keyman = NewKeyManager(p)

// var keyman interfaces.KeyManager = (*keyManager)(y)

func TestRegisterProvider(t *testing.T) {
	id := "afe4a898-2582-482d-b82d-43a592a40373"
	name := "Test Certificate File Provider"
	private := "Keys/privatekeyRSA.pem"
	public := "Keys/publickeyRSA.pem"
	algorithm := "rsa"
	jj := NewCrtFileProvider(id, name, private, public, algorithm)
	keyman.RegisterProvider(jj)
}

func TestGeyKeyByProviderId(t *testing.T) {
	//assumes RSA, do not change key files or string values
	id := "afe4a898-2582-482d-b82d-43a592a40373"
	k := keyman.GetKeyByProviderId(id)
	var bignum, _ = new(big.Int).SetString("21086672194055230843612669443904574149811002047199307203395284381153222757946337921885021264571719641013039076957836127385367613397254088944127537594742835698599342510485047377962431798843899579770319434276737961042366904179340813692562855003898865028195278616282018741182344735960747779342416070036207295835459331516253126867178440116447801834476800207659890363928165409520291568362358485983049331749816176659779777775050704230265170530312109028338452264162399421025001847654072603050778790932784226771957796904573649393088878115602311774948562636636391090805302582907612057686556952164829704687199975950062033355959", 0)
	expectedPublic := rsa.PublicKey{
		N: bignum,
		E: 65537,
	}
	expectedPrivate := rsa.PrivateKey{
		PublicKey: expectedPublic,
	}
	expectedKey := types.Key{
		PublicKey:  expectedPublic,
		PrivateKey: expectedPrivate,
		Thumbprint: []int{},
		KeyId:      nil,
	}

	pub := k.PublicKey.(*rsa.PublicKey).N.String()
	priv := k.PrivateKey.(*rsa.PrivateKey).N.String()

	if pub != expectedPublic.N.String() || priv != expectedPrivate.N.String() {
		t.Errorf("Expected %s, got %s", pub, expectedPrivate.N.String())
	}
	if expectedPrivate.PublicKey.Equal(&k.PublicKey) {
		t.Errorf("Expected %d, got %d", &expectedPrivate.PublicKey, k.PublicKey)
	}
	log.Println("entire expected key is", expectedKey)
}

func TestRefreshKey(t *testing.T) {
	id := "afe4a898-2582-482d-b82d-43a592a40373"
	keyman.RefreshKey(id)
}

func TestRefreshAllKeys(t *testing.T) {
	keyman.RefreshAllKeys()
}
func TestDeleteProvider(t *testing.T) {
	id := "afe4a898-2582-482d-b82d-43a592a40373"
	keyman.DeleteProvider(id)
}
