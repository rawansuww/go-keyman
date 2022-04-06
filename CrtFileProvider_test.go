package gokeyman

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/rawansuww/go-keyman/types"
)

func TestGetIdentifier(t *testing.T) {
	id := uuid.New().String()
	name := "Test Certificate File Provider"
	public := "Keys/publickey.pem"
	private := "Keys/privatekey.pem"
	algorithm := "rsa"
	jj := NewCrtFileProvider(id, name, public, private, algorithm)

	var expected = id
	id_test := jj.GetIdentifier()

	fmt.Println(id_test)
	if id_test != expected {
		t.Errorf("Expected %s, got %s", expected, id_test)
	}

}

func TestFetchKeysFromStore(t *testing.T) {
	id := uuid.New().String()
	name := "Test Certificate File Provider"
	public := "Keys/publickey.pem"
	private := "Keys/privatekey.pem"
	algorithm := "rsa"
	jj := NewCrtFileProvider(id, name, private, public, algorithm)

	key, err := jj.FetchKeyFromStore()
	if err != (types.InternalError{}) {
		fmt.Println(err)
	}
	// var x *rsa.PublicKey{
	// 	N:,
	// 	E
	// }
	fmt.Println(reflect.TypeOf(key.PublicKey))
	fmt.Println(key.PublicKey)
	fmt.Println(key.PrivateKey)
	fmt.Println(key.Thumbprint)
	fmt.Println(key.KeyId)
	expected:=types.Key{
		PublicKey: ,
		PrivateKey: ,
		Thumbprint: ,
		KeyId: nil,
	}

	// if err != (types.InternalError{}) {
	// 	t.Errorf("what", err)
	// }
	// if id_test != expected {
	// 	t.Errorf("Expected %d, got %d", expected, id_test)
	// }

}

// func TestJsonPost(t *testing.T) {
// 	ep := "http://localhost:3000/"
// 	cl := gorest.NewClient()

// 	cl.SetBaseUrl(ep)

// 	expected := map[string]string{
// 		"name": "Aranyak Ghosh",
// 	}
// 	var data map[string]string

// 	resp := cl.Post("", nil, nil, expected, types.JSON)

// 	if resp.Error() != nil {
// 		t.Errorf("Expected no error, got %v", resp.Error())
// 	} else if !resp.IsSuccessfulResponse() {
// 		t.Errorf("Expected success status, got %d", resp.Status())
// 	} else {
// 		resp.Result(&data)
// 		if !reflect.DeepEqual(data, expected) {
// 			t.Errorf("Expected %v, got %v", expected, data)
// 		}
// 	}
// }

// func TestListLenght(t *testing.T) {
// 	var q List[int]

// 	var expected = 1

// 	q.Append(5)

// 	len := q.Length()

// 	if expected != len {
// 		t.Errorf("Expected %d, got %d", expected, len)
// 	}
// }

// func TestListRemoveAt(t *testing.T) {
// 	var q List[int]

// 	var expected = 1

// 	q.Append(expected)

// 	var i = q[0]
// 	if i != expected {
// 		t.Errorf("Expected %d, got %d", expected, i)
// 	}

// 	q.RemoveAt(0)

// 	if q.Length() != 0 {
// 		t.Errorf("Expected %d, got %d", 0, q.Length())
// 	}

// }

// func TestListFilter(t *testing.T) {
// 	var q *List[int] = new(List[int])

// 	*q = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

// 	var expected = []int{2, 4, 6, 8, 10}

// 	q = (q.Filter(func(x int) bool {
// 		return x%2 == 0
// 	})).(*List[int])

// 	for i := range expected {
// 		if (*q)[i] != expected[i] {
// 			t.Errorf("Expected %d, got %d", expected[i], (*q)[i])
// 			break
// 		}
// 	}
// }

// func TestListMap(t *testing.T) {
// 	var q *List[int] = new(List[int])

// 	*q = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

// 	var expected = []string{"plsWork-1", "plsWork-2", "plsWork-3", "plsWork-4", "plsWork-5", "plsWork-6", "plsWork-7", "plsWork-8", "plsWork-9", "plsWork-10"}

// 	res := (q.Map(func(x int) any {
// 		return fmt.Sprintf("plsWork-%d", x)
// 	})).(*List[any])

// 	for i := range expected {
// 		if (*res)[i] != expected[i] {
// 			t.Errorf("Expected %s, got %s", expected[i], (*res)[i])
// 			break
// 		}
// 	}
// }
