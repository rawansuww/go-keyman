package gokeyman

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/rawansuww/go-keyman/interfaces"
	"github.com/rawansuww/go-keyman/types"
)

//did not understand how to get thumb and kid
type crtFileProvider struct {
	id          string
	name        string
	privatePath string
	publicPath  string
	algorithm   string
}

var _ interfaces.Provider = (*crtFileProvider)(nil)

func (p *crtFileProvider) GetIdentifier() (x string) {
	return p.id
}

//FILE VALIDATION : CONTENT AND FILE TYPE
func (p *crtFileProvider) FetchKeyFromStore() (types.Key, types.InternalError) {
	var decodedPriv, decodedPublic []byte
	var err types.InternalError
	if p.privatePath == "" && p.publicPath == "" {
		return types.Key{}, types.InternalError{ErrorMessage: "No path for both private and public key was specified"}
	}

	if p.privatePath != "" {
		privKey, err1 := os.ReadFile(p.privatePath)
		if err1 != nil {
			log.Println("Error reading private key FILE, or path does not exist")
			return types.Key{}, types.InternalError{ErrorMessage: "Error reading private key file", ErrorDetails: err1}
		}
		decodedPriv, err = parseDecodeKey(privKey, p.algorithm)

	}

	if p.publicPath != "" {
		pubKey, err1 := os.ReadFile(p.publicPath)
		if err1 != nil {
			log.Println("Error reading private key FILE, or path does not exist")
			return types.Key{}, types.InternalError{ErrorMessage: "Error reading private key file", ErrorDetails: err1}
		}
		decodedPublic, err = parseDecodeKey(pubKey, p.algorithm)

	}

	return types.Key{
		PrivateKey: decodedPriv,
		PublicKey:  decodedPublic,
		//Thumbprint: thumb,
		//KeyId:      kid,
	}, err
}

func NewCrtFileProvider(id string, name string, privatePath string, publicPath string, algo string) *crtFileProvider {
	return &crtFileProvider{
		id:          id,
		name:        name,
		privatePath: privatePath,
		publicPath:  publicPath,
	}
}

func getThumb(publicKey []byte) (x []byte) {
	// pass cert bytes
	block, _ := pem.Decode(publicKey)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	fingerprint := sha1.Sum(cert.Raw)
	var buf bytes.Buffer
	for i, f := range fingerprint {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}
	fmt.Printf("Fingerprint: %s\n", buf.String())
	return []byte(buf)
}

func parseDecodeKey(key []byte, algo string) ([]byte, types.InternalError) {
	var decodedKey []byte
	PEMString := "(-----BEGIN .+?-----(?s).+?-----END .+?-----)"
	ok, err := regexp.MatchString(PEMString, string(key))
	if err != nil {
		fmt.Println("your regex is faulty")
	}
	if !ok {
		log.Println("Key file does not follow proper format.")
		return []byte(""), types.InternalError{ErrorMessage: "Key file does not follow proper format.", ErrorDetails: err}
	}
	block, _ := pem.Decode(key)
	if block == nil {
		log.Fatalf("bad key data: %s", "not PEM-encoded")
		return []byte(""), types.InternalError{ErrorMessage: "Decoding bad PEM", ErrorDetails: err}
	}
	if block.Type != algo { //need to handle rest of types
		//throw error to say the sent PEM isnt same as  desired algorithm
		//although it's probably faster to just check block.Type and decode accordingly, without extra field of algo
	}

	if algo == "rsa" {
		pk, err := x509.ParsePKCS1PublicKey(block.Bytes)
		v := []byte(pk)
		if err != nil {
			log.Fatalf("parse bad private key: %s", err)
			return []byte(""), types.InternalError{ErrorMessage: "Parsing bad private key.", ErrorDetails: err}
		}

	} else if algo == "hsa" {
	} else if algo == "" {
	}

	return decodedKey, types.InternalError{}
}
