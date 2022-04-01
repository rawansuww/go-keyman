package implementation

import (
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/rawansuww/go-keyman/types"
	"go.uber.org/fx"
)

type fileProvider struct {
	id          string
	name        string
	privatePath string
	publicPath  string
	thumbPath   string
	kidPath     string
}

func (p *fileProvider) GetIdentifier() (x string) {
	return p.id
}

//FILE VALIDATION : CONTENT AND FILE TYPE
//just basic regex for now...
//REMEMBER TO ADD CONSTRUCTORS AND INJECTIONS EVERYWHERE
func (p *fileProvider) FetchKeyFromStore() types.Key {
	PEMString := "(-----BEGIN .+?-----(?s).+?-----END .+?-----)"
	privKey, error := os.ReadFile(p.privatePath)
	if error != nil {
		//readFile error
	}
	ok, err := regexp.MatchString(PEMString, string(privKey))
	if err != nil {
		fmt.Println("your regex is faulty")
	}
	if !ok {
		log.Println("Private PEM file does not follow proper format.")
		return types.Key{}
	}

	pubKey, err1 := os.ReadFile(p.publicPath)
	if err1 != nil {
		//readFile error
	}
	ok, err = regexp.MatchString(PEMString, string(pubKey))
	if err != nil {
		fmt.Println("your regex is faulty")
	}
	if !ok {
		log.Println("Private PEM file does not follow proper format.")
		return types.Key{}
	}

	thumb, _ := os.ReadFile(p.thumbPath)
	if err1 != nil {
		//readFile error
	}

	kid, _ := os.ReadFile(p.kidPath)
	if err1 != nil {
		//readFile error
	}

	return types.Key{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Thumbprint: thumb,
		KeyId:      kid,
	}
}

func NewFileProvider(id string, name string, privatePath string, publicPath string, thumbPath string, kidPath string) *fileProvider {
	return &fileProvider{
		id:          id,
		name:        name,
		privatePath: privatePath,
		publicPath:  publicPath,
		thumbPath:   thumbPath,
		kidPath:     kidPath,
	}
}

var Module = fx.Options(
	fx.Provide(NewFileProvider),
)
