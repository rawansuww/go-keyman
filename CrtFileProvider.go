package gokeyman

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/rawansuww/go-keyman/interfaces"
	"github.com/rawansuww/go-keyman/types"
)

var (
	ErrNotECPublicKey   = errors.New("Key is not a valid ECDSA public key")
	ErrNotECPrivateKey  = errors.New("Key is not a valid ECDSA private key")
	ErrNotRSAPublicKey  = errors.New("Key is not a valid RSA public key")
	ErrNotRSAPrivateKey = errors.New("Key is not a valid RSA private key")
	ErrFileFormat       = errors.New("Key file does not follow proper format")
	ErrBadPEM           = errors.New("Bad key data")
	ErrParsePrivate     = errors.New("Error parsing the private key")
	ErrParsePublic      = errors.New("Error parsing the public key")
	ErrBadRegex         = errors.New("Regex is faulty")
)

type crtFileProvider struct {
	id          string
	name        string
	privatePath string
	publicPath  string
}

var _ interfaces.Provider = (*crtFileProvider)(nil)

func (p *crtFileProvider) GetIdentifier() (x string) {
	return p.id
}

//FILE VALIDATION : CONTENT AND FILE TYPE
func (p *crtFileProvider) FetchKeyFromStore() (types.Key, types.InternalError) {
	var decodedPriv, decodedPublic, thumbPrint []byte
	var err types.InternalError
	if p.privatePath == "" && p.publicPath == "" {
		return types.Key{}, types.InternalError{ErrorDetails: errors.New("No path for both private and public key was specified")}
	}

	if p.privatePath != "" {
		privKey, err1 := os.ReadFile(p.privatePath)
		if err1 != nil {
			log.Println("Error reading private key FILE, or path does not exist")
			return types.Key{}, types.InternalError{ErrorMessage: "Error reading private key file", ErrorDetails: err1}
		}
		decodedPriv, err = DecodePrivateKey(privKey)

	}

	if p.publicPath != "" {
		pubKey, err1 := os.ReadFile(p.publicPath)
		if err1 != nil {
			log.Println("Error reading private key FILE, or path does not exist")
			return types.Key{}, types.InternalError{ErrorMessage: "Error reading private key file", ErrorDetails: err1}
		}
		decodedPublic, thumbPrint, err = DecodePublicKey(pubKey)

	}

	return types.Key{
		PrivateKey: decodedPriv,
		PublicKey:  decodedPublic,
		Thumbprint: thumbPrint,
		KeyId:      thumbPrint,
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

//deccode the public key
func DecodePublicKey(key []byte) ([]byte, []byte, types.InternalError) {
	var decodedKey []byte
	PEMString := "(-----BEGIN .+?-----(?s).+?-----END .+?-----)"
	ok, err := regexp.MatchString(PEMString, string(key))
	if err != nil {
		log.Println("Faulty regex")
		return nil, nil, types.InternalError{ErrorMessage: "Bad regex", ErrorDetails: ErrBadRegex}
	}
	if !ok {
		log.Println("Key file does not follow proper format.")
		return nil, nil, types.InternalError{ErrorMessage: "Key does not follow format", ErrorDetails: ErrFileFormat}
	}
	block, _ := pem.Decode(key)
	cert, err := x509.ParseCertificate(block.Bytes)

	if block == nil {
		log.Fatalf("bad key data: %s", "not PEM-encoded")
		return nil, nil, types.InternalError{ErrorMessage: "Decoding bad PEM", ErrorDetails: ErrBadPEM}
	}
	if cert.PublicKeyAlgorithm == x509.RSA {
		//get the key
		parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		cert, err := x509.ParseCertificate(block.Bytes)
		parsedKey = cert.PublicKey

		//check if key type is actually RSA
		var pkey *rsa.PublicKey
		var ok bool
		if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
			return nil, nil, types.InternalError{ErrorDetails: ErrNotRSAPrivateKey}

			decodedKey = x509.MarshalPKCS1PublicKey(pkey) //marshal the key back into []byte format so that we may store it
		} else if cert.PublicKeyAlgorithm == x509.ECDSA {
			// Parse the key
			var parsedKey interface{}
			if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					parsedKey = cert.PublicKey
				} else {
					return nil, nil, types.InternalError{ErrorDetails: ErrParsePublic}
				}
			}

			var pkey *ecdsa.PublicKey
			var ok bool
			if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
				return nil, nil, types.InternalError{ErrorDetails: ErrNotECPublicKey}
			}
			decodedKey, _ = x509.MarshalPKIXPublicKey(pkey) //marshal the key back into []byte format so that we may store it
		}
	}
	fingerprint := sha1.Sum(cert.Raw)
	thumbPrint := fingerprint[:]
	return decodedKey, thumbPrint, types.InternalError{}
}

//decode the private key
func DecodePrivateKey(key []byte) ([]byte, types.InternalError) {
	var decodedKey []byte
	PEMString := "(-----BEGIN .+?-----(?s).+?-----END .+?-----)"
	ok, err := regexp.MatchString(PEMString, string(key))
	if err != nil {
		fmt.Println("your regex is faulty")
	}
	if !ok {
		log.Println("Key file does not follow proper format.")
		return []byte(""), types.InternalError{ErrorMessage: "Key does not follow proper format.", ErrorDetails: ErrFileFormat}
	}
	block, _ := pem.Decode(key)
	if block == nil {
		log.Fatalf("bad key data: %s", "not PEM-encoded")
		return []byte(""), types.InternalError{ErrorMessage: "Decoding bad PEM", ErrorDetails: ErrBadPEM}
	}

	cert, err := x509.ParseCertificate(block.Bytes)

	if cert.PublicKeyAlgorithm == x509.RSA {
		var pkey *rsa.PrivateKey
		var ok bool
		var parsedKey interface{}
		if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				return nil, types.InternalError{ErrorDetails: err}
			}
		}
		if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
			return nil, types.InternalError{ErrorDetails: ErrNotECPrivateKey}
		}
		decodedKey = x509.MarshalPKCS1PrivateKey(pkey) //marshal the key back into []byte format so that we may store it

	} else if cert.PublicKeyAlgorithm == x509.ECDSA {
		// Parse the key
		var pkey *ecdsa.PrivateKey
		var ok bool
		var parsedKey interface{}
		if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
			if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				return nil, types.InternalError{ErrorDetails: ErrParsePrivate}
			}
		}
		if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
			return nil, types.InternalError{ErrorDetails: ErrNotECPrivateKey}
		}
		decodedKey, _ = x509.MarshalECPrivateKey(pkey) //marshal the key back into []byte format so that we may store it
	}

	return decodedKey, types.InternalError{}
}
