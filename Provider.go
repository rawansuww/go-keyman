package gokeyman

import (
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/rawansuww/go-keyman/interfaces"
	"github.com/rawansuww/go-keyman/types"
)

type fileProvider struct {
	id          string
	name        string
	privatePath string
	publicPath  string
	thumbPath   string
	kidPath     string
}

var _ interfaces.Provider = (*fileProvider)(nil)

func (p *fileProvider) GetIdentifier() (x string) {
	return p.id
}

//FILE VALIDATION : CONTENT AND FILE TYPE
func (p *fileProvider) FetchKeyFromStore() (types.Key, error) {
	PEMString := "(-----BEGIN .+?-----(?s).+?-----END .+?-----)"
	privKey, err1 := os.ReadFile(p.privatePath)
	if err1 != nil {
		log.Println("Error reading private key path!")
		return types.Key{}, err1
	}
	ok, err := regexp.MatchString(PEMString, string(privKey))
	if err != nil {
		fmt.Println("your regex is faulty")
	}
	if !ok {
		log.Println("Private key file does not follow proper format.")
		return types.Key{}, err
	}

	pubKey, err1 := os.ReadFile(p.publicPath)
	if err1 != nil {
		log.Println("Error reading public key path!")
		return types.Key{}, err1
	}
	ok, err = regexp.MatchString(PEMString, string(pubKey))
	if err != nil {
		fmt.Println("your regex is faulty")
	}
	if !ok {
		log.Println("Public key file does not follow proper format.")
		return types.Key{}, err
	}

	thumb, _ := os.ReadFile(p.thumbPath)
	if err1 != nil {
		log.Println("Error reading thumbprint path!")
		return types.Key{}, err1
	}

	kid, _ := os.ReadFile(p.kidPath)
	if err1 != nil {
		log.Println("Error reading KID path!")
		return types.Key{}, err1
	}

	return types.Key{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Thumbprint: thumb,
		KeyId:      kid,
	}, nil
}

func NewFileProvider(id string, name string, privatePath string, publicPath string, algo string) *fileProvider {
	return &fileProvider{
		id:          id,
		name:        name,
		privatePath: privatePath,
		publicPath:  publicPath,
	}
}
