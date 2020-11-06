package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

//Tests if properly returns error if try to 
//initialize a username already in existence 
func TestUserExists(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	_, err1 := InitUser("alice", "fubar1")
	if err1 == nil {
		t.Error("Failed: Initialized 2 users with same username")
		return
	}

	t.Log("Got error", err1)
}

//Tests if able to properly retreive a user from Datastore
//and if able to create more than one instance of same user 
func TestUserGet(t *testing.T) {
	clear()

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, _ := InitUser("alice", "fubar")

	get_u, err := GetUser("alice", "fubar")

	if err != nil {
		t.Log("Got error", err)
		return
	}

	if !reflect.DeepEqual(u, get_u) {
		t.Error("initialized and stored user are not equal")
		t.Log("Got user", get_u)
		return 
	}

	get_u1, err := GetUser("alice", "fubar")

	if err != nil {
		t.Log("Got error on 2nd GetUser", err)
		return
	}

	if !reflect.DeepEqual(get_u1, get_u) {
		t.Error("2 instances of stored user are not equal")
		t.Log("Got user", get_u1)
		return 
	}

}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

//Checks that StoreFile works properly 
//tests if able to overwrite file with same filename
func TestStoreFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v1 := []byte("Overwrite data")
	u.StoreFile("file1", v1)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}

	if !reflect.DeepEqual(v1, v2) {
		t.Error("Downloaded file is not the same", v1, v2)
		return
	}

} 

//Tests to make sure LoadFile does not load data that should 
//only be accessed by one user 
func TestLoadFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	u1, err := InitUser("charles", "dance")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u1.LoadFile("file1")
	if err2 == nil {
		t.Error("Failed to recognize filename should not exist under user", err2)
		return
	}

	t.Log("Got error", err2)
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

//Ensures that AppendFile's basic functionality is working
func TestAppendFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	apData := []byte("this is appended data")
	err = u.AppendFile("file1", apData)
	if err != nil {
		t.Error("Error while appending data:", err)
	}

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to load data after appending", err2)
		return
	}

	original := appendData(apData, v)
	if !reflect.DeepEqual(original, v2) {
		t.Error("appended data from Datastore is not equal to original", v2, original)
		return
	}

}


func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	
	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}
