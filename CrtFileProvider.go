package gokeyman

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"regexp"

	"github.com/rawansuww/go-keyman/interfaces"
	"github.com/rawansuww/go-keyman/types"
)

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

func (p *crtFileProvider) FetchKeyFromStore() (types.Key, types.InternalError) {
	var decodedPriv, decodedPublic, thumbPrint any
	var err types.InternalError
	if p.privatePath == "" && p.publicPath == "" {
		return types.Key{}, types.InternalError{ErrorDetails: errors.New("No path for both private and public key was specified")}
	}

	if p.privatePath != "" { //not null private path
		privKey, err1 := os.ReadFile(p.privatePath)
		if err1 != nil {
			return types.Key{}, types.InternalError{ErrorMessage: "Error reading private key file", ErrorDetails: err1}
		}
		if p.algorithm == "RSA" || p.algorithm == "rsa" { //check against supplied algorithm type
			decodedPriv, err = RSAPrivateKeyFromPEM(privKey)
		} else if p.algorithm == "ECDSA" || p.algorithm == "ecdsa" {
			decodedPriv, err = ECDSAPrivateKeyFromPEM(privKey)
		}

	}

	if p.publicPath != "" { //not null public path
		pubKey, err1 := os.ReadFile(p.publicPath)
		if err1 != nil {
			log.Println("Error reading public key FILE, or path does not exist")
			return types.Key{}, types.InternalError{ErrorMessage: "Error reading public key file", ErrorDetails: err1}
		}
		if p.algorithm == "RSA" || p.algorithm == "rsa" { //check against supplied algorithm type
			decodedPublic, thumbPrint, err = RSAPublicKeyFromPEM(pubKey)
		} else if p.algorithm == "ECDSA" || p.algorithm == "ecdsa" {
			decodedPublic, thumbPrint, err = ECDSAPublicKeyFromPEM(pubKey)
		}

	}

	return types.Key{
		PrivateKey: decodedPriv,
		PublicKey:  decodedPublic,
		Thumbprint: thumbPrint,
		KeyId:      nil,
	}, err
}

//deccode RSA public key
func RSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, []byte, types.InternalError) {
	//regex
	if regex := Regex(string(key)); regex != nil {
		return nil, nil, types.InternalError{ErrorMessage: regex.Error(), ErrorDetails: regex}
	}

	//decode PEM block
	var err error
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, nil, types.InternalError{ErrorMessage: "failed to decode RSA PEM block"}
	}

	//parse key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				parsedKey = cert.PublicKey
				fingerprint := sha1.Sum(cert.Raw)
				thumbPrint := fingerprint[:]
				return parsedKey.(*rsa.PublicKey), thumbPrint, types.InternalError{}
			} else {
				return nil, nil, types.InternalError{ErrorMessage: "Failed to parse RSA public key", ErrorDetails: err}
			}
		}
	}
	//validate RSA type
	if pkey, okay := parsedKey.(*rsa.PublicKey); okay {
		return pkey, nil, types.InternalError{} //if no certificate supplied, thumbprint is nil
	}
	return nil, nil, types.InternalError{ErrorMessage: "Decoding RSA key from file failed"}

}

//decode RSA private key
func RSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, types.InternalError) {
	//regex
	if regex := Regex(string(key)); regex != nil {
		return nil, types.InternalError{ErrorMessage: regex.Error(), ErrorDetails: regex}
	}
	//decode PEM block
	var err error
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, types.InternalError{ErrorMessage: "failed to decode RSA PEM block"}
	}
	//parse key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, types.InternalError{ErrorMessage: "Failed to parse RSA private key", ErrorDetails: err}
		}
	}
	//validate RSA type
	if pkey, okay := parsedKey.(*rsa.PrivateKey); okay {
		return pkey, types.InternalError{}
	}
	return nil, types.InternalError{ErrorMessage: "Decoding RSA private key from file failed"}
}

//deccode ECDSA public key
func ECDSAPublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, []byte, types.InternalError) {
	//regex
	if regex := Regex(string(key)); regex != nil {
		return nil, nil, types.InternalError{ErrorMessage: regex.Error(), ErrorDetails: regex}
	}

	//decode PEM block
	var err error
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, nil, types.InternalError{ErrorMessage: "failed to decode ECDSA PEM block"}
	}

	//parse key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
			fingerprint := sha1.Sum(cert.Raw)
			thumbPrint := fingerprint[:]
			return parsedKey.(*ecdsa.PublicKey), thumbPrint, types.InternalError{}
		} else {
			return nil, nil, types.InternalError{ErrorMessage: "Failed to parse public ECDSA key", ErrorDetails: err}
		}
	}
	//validate RSA type
	if pkey, okay := parsedKey.(*ecdsa.PublicKey); okay {
		return pkey, nil, types.InternalError{} //if no certificate supplied, thumbprint is nil
	}
	return nil, nil, types.InternalError{ErrorMessage: "Decoding ECDSA key from file failed"}

}

//decode ECDSA private key
func ECDSAPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, types.InternalError) {
	//regex
	if regex := Regex(string(key)); regex != nil {
		return nil, types.InternalError{ErrorMessage: regex.Error(), ErrorDetails: regex}
	}
	//decode PEM block
	var err error
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, types.InternalError{ErrorMessage: "failed to decode ECDSA PEM block"}
	}
	//parse key
	var parsedKey interface{}
	if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, types.InternalError{ErrorMessage: "Failed to parse ECDSA private key", ErrorDetails: err}
		}
	}
	//validate RSA type
	if pkey, okay := parsedKey.(*ecdsa.PrivateKey); okay {
		return pkey, types.InternalError{}
	}
	return nil, types.InternalError{ErrorMessage: "Decoding ECDSA private key from file failed"}
}

//regex check
func Regex(try string) error {
	PEMString := "(-----BEGIN .+?-----(?s).+?-----END .+?-----)"
	ok, error := regexp.MatchString(PEMString, try)
	if error != nil {
		log.Println("bad or faulty regex")
		return error
	} else if !ok {
		log.Println("string did not match AKA key format not followed")
		return errors.New("Key file format not followed")
	}
	return nil
}

func NewCrtFileProvider(id string, name string, privatePath string, publicPath string, algorithm string) *crtFileProvider {
	return &crtFileProvider{
		id:          id,
		name:        name,
		privatePath: privatePath,
		publicPath:  publicPath,
		algorithm:   algorithm,
	}
}
