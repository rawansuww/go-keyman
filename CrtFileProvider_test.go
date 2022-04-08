package gokeyman

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"log"
	"math/big"
	"testing"

	"github.com/google/uuid"
	"github.com/rawansuww/go-keyman/types"
)

var id = uuid.New().String()
var name = "Test Certificate File Provider"
var public = "Keys/publickeyRSA.pem"
var private = "Keys/privatekeyRSA.pem"
var algorithm = "rsa"
var provider = NewCrtFileProvider(id, name, private, public, algorithm)

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

func TestFetchKeysFromStoreECDSA(t *testing.T) {
	id = uuid.New().String()
	name = "Test Certificate File Provider"
	public = "Keys/publickeyECDSA.pem"
	private = "Keys/privatekeyECDSA.pem"
	algorithm = "ecdsa"
	provider = NewCrtFileProvider(id, name, private, public, algorithm)

	key, err := provider.FetchKeyFromStore()
	if err != (types.InternalError{}) {
		t.Error("Could not fetch key", err)
	}

	var expectedX, _ = new(big.Int).SetString("25727263160606014701617924262170986425071921436682833371460149464704535570409034947396711600112845935900453309273541", 0)
	var expectedY, _ = new(big.Int).SetString("3315828504995314496719828189173165164911681772154326282451119145049787840765532278823003223491504798895786451401607", 0)
	var expectedD, _ = new(big.Int).SetString("38938228806320969723008876951852467081365454157553071870509919438539548879688684039794013814786048635598982315899317", 0)

	expectedPublic := ecdsa.PublicKey{
		X: expectedX,
		Y: expectedY,
	}

	expectedPrivate := ecdsa.PrivateKey{
		PublicKey: expectedPublic,
		D:         expectedD,
	}

	pubX := key.PublicKey.(*ecdsa.PublicKey).X.String()
	pubY := key.PublicKey.(*ecdsa.PublicKey).Y.String()
	privD := key.PrivateKey.(*ecdsa.PrivateKey).D.String()

	if pubX != expectedPublic.X.String() || pubY != expectedPublic.Y.String() {
		t.Errorf("Expected %s%s, got %s%s", pubX, pubY, expectedPublic.X.String(), expectedPublic.Y.String())
	}

	if privD != expectedPrivate.D.String() {
		t.Errorf("Expected %s, got %s", privD, expectedPrivate.D.String())
	}

	if expectedPrivate.PublicKey.Equal(&key.PublicKey) {
		t.Errorf("Key pair verify, exxpected %d, got %d", &expectedPrivate.PublicKey, key.PublicKey)
	}

}
