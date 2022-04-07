package gokeyman

import (
	"crypto/rsa"
	"log"
	"math/big"
	"testing"

	"github.com/google/uuid"
	"github.com/rawansuww/go-keyman/interfaces"
	"github.com/rawansuww/go-keyman/types"
)

var id = uuid.New().String()
var name = "Test Certificate File Provider"
var public = "Keys/publickey.pem"
var private = "Keys/privatekey.pem"
var algorithm = "rsa"
var crtProvider = NewCrtFileProvider(id, name, public, private, algorithm)
var provider interfaces.Provider = (*crtFileProvider)(crtProvider)

func TestGetIdentifier(t *testing.T) {
	var expected = id
	id_test := provider.GetIdentifier()
	log.Println(id_test)
	if id_test != expected {
		t.Errorf("Expected %s, got %s", expected, id_test)
	}
}

func TestFetchKeysFromStoreRSA(t *testing.T) {
	key, err := provider.FetchKeyFromStore()
	if err != (types.InternalError{}) {
		t.Errorf("Could not fetch key")
	}

	//note: privatekey.N and publickey.N have same modulus value as key pairs, which is why i'm setting their bigInt value as same
	//adjust bignum values according to changed .pem files
	//do not use same bignum if not priv/public keyPair (if not share same modulus)
	var bignum, _ = new(big.Int).SetString("21086672194055230843612669443904574149811002047199307203395284381153222757946337921885021264571719641013039076957836127385367613397254088944127537594742835698599342510485047377962431798843899579770319434276737961042366904179340813692562855003898865028195278616282018741182344735960747779342416070036207295835459331516253126867178440116447801834476800207659890363928165409520291568362358485983049331749816176659779777775050704230265170530312109028338452264162399421025001847654072603050778790932784226771957796904573649393088878115602311774948562636636391090805302582907612057686556952164829704687199975950062033355959", 0)

	expectedPublic := rsa.PublicKey{
		N: bignum,
		E: 65537,
	}

	expectedPrivate := rsa.PrivateKey{
		PublicKey: expectedPublic,
	}

	pub := key.PublicKey.(*rsa.PublicKey).N.String()
	priv := key.PrivateKey.(*rsa.PrivateKey).N.String()

	if pub != expectedPublic.N.String() || priv != expectedPrivate.N.String() {
		t.Errorf("Expected %s, got %s", pub, expectedPrivate.N.String())
	}

	if expectedPrivate.PublicKey.Equal(&key.PublicKey) {
		t.Errorf("Expected %d, got %d", &expectedPrivate.PublicKey, key.PublicKey)
	}

}
