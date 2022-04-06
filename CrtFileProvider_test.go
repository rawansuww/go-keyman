package gokeyman

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestGetIdentifier(t *testing.T) {
	id := uuid.New().String()
	name := "Test Certificate File Provider"
	public := "/Keys/publickey.pem"
	private := "/Keys/privatekey.pem"
	algorithm := "rsa"
	jj := NewCrtFileProvider(id, name, public, private, algorithm)

	var expected = id
	id_test := jj.GetIdentifier()

	if id_test != expected {
		t.Errorf("Expected %d, got %d", expected, id_test)
	}

}

func TestFetchKeysFromStore(t *testing.T) {
	id := uuid.New().String()
	name := "Test Certificate File Provider"
	public := "/Keys/publickey.pem"
	private := "/Keys/privatekey.pem"
	algorithm := "rsa"
	jj := NewCrtFileProvider(id, name, public, private, algorithm)

	key, _ := jj.FetchKeyFromStore()
	fmt.Println(key)
	// if err != (types.InternalError{}) {
	// 	t.Errorf("what", err)
	// }
	// if id_test != expected {
	// 	t.Errorf("Expected %d, got %d", expected, id_test)
	// }

}
