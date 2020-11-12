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

func TestUserGet_BadInput(t *testing.T) {
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
	_, err = GetUser("alice", "fubar2020")
	if err != nil {
		t.Log("Got error with wrong password", err)
		return
	}

	_, err = GetUser("alice_", "fubar")
	if err != nil {
		t.Log("Got error with wrong username", err)
		return
	}
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

//basic Store/Load file functionality
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

	u1, _ := GetUser("alice", "fubar")
	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v1 := []byte("Overwrite data")
	u.StoreFile("file1", v1)

	v2, err2 := u1.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}

	if !reflect.DeepEqual(v1, v2) {
		t.Error("Downloaded file is not the same", v1, v2)
		return
	}
}

//Tests if another instance of a user makes a new file,
//the original user has access to the file
func Test_StoreFiles(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u1, _ := GetUser("alice", "fubar")
	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v1 := []byte("new data for new file")
	u1.StoreFile("file2", v1)

	v2, err2 := u.LoadFile("file2")
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

	apData := []byte(" this is appended data")
	u1, _ := GetUser("alice", "fubar")
	err = u1.AppendFile("file1", apData)
	if err != nil {
		t.Error("Error while appending data:", err)
	}

	apData1 := []byte(" even more new data")
	err = u.AppendFile("file1", apData1)
	if err != nil {
		t.Error("Error while appending data 2nd time:", err)
	}
	v2, err2 := u1.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to load data after appending", err2)
		return
	}

	original := v
	for i := 0; i < len(apData); i++ {
		original = append(original, apData[i])
	}
	for i := 0; i < len(apData1); i++ {
		original = append(original, apData1[i])
	}

	if !reflect.DeepEqual(original, v2) {
		t.Error("appended data from Datastore is not equal to original", string(v2), string(original))
		return
	}

	v3, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to load data after appending", err2)
		return
	}

	if !reflect.DeepEqual(v3, v2) {
		t.Error("appended data from Datastore is not equal to original", string(v2), string(v3))
		return
	}
}

//Makes sure user without access to a file can't append to it
func TestInvalidAppend(t *testing.T) {
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

	apData1 := []byte("new data")
	err = u2.AppendFile("file1", apData1)
	if err == nil {
		t.Error("Unauthorized user was able to append to file", err)
	}
	t.Log("got error", err)
	return
}

//Makes sure user can't append to a file that doesn't exist
func TestAppend_WrongInput(t *testing.T) {
	clear()
	u2, err := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return
	}

	apData1 := []byte("new data")
	err = u2.AppendFile("file5", apData1)
	if err == nil {
		t.Error("attempted to append to a file that doesn't exist", err)
	}
	t.Log("got error", err)
	return
}

//Tests basic share functionality
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

//Tests that user with shared file is able to load appended data
//that was done by another user
func TestShareAppend(t *testing.T) {
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

	apData1 := []byte(" this is appended data")
	err = u.AppendFile("file1", apData1)
	if err != nil {
		t.Error("Error while appending data", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after appending", err)
		return
	}

	original := v
	for i := 0; i < len(apData1); i++ {
		original = append(original, apData1[i])
	}

	if !reflect.DeepEqual(original, v2) {
		t.Error("appended data from Datastore is not equal to original", string(v2), string(original))
		return
	}

}

//tests that sequential store and appends to a file
//are reflected across all users with access
func TestShareModify(t *testing.T) {
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
	var magic_string string

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

	apData1 := []byte(" this is appended data")
	err = u.AppendFile("file1", apData1)
	if err != nil {
		t.Error("Error while appending data", err)
	}

	apData2 := []byte(" this is more appended data")
	err = u2.AppendFile("file2", apData2)
	if err != nil {
		t.Error("Error while appending data", err)
	}

	v_loaded, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file", err)
		return
	}
	v2_loaded, err := u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to load file", err)
		return
	}

	if !reflect.DeepEqual(v2_loaded, v_loaded) {
		t.Error("appended data from Datastore is not equal to original", string(v_loaded), string(v2_loaded))
		return
	}

	v2 := []byte("This should overwrite file")
	u2.StoreFile("file2", v2)
	v3_loaded, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file", err)
		return
	}

	if !reflect.DeepEqual(v3_loaded, v2) {
		t.Error("stored data from Datastore is not equal to original", string(v2), string(v3_loaded))
		return
	}
}

//tests that a modified access token is able to be detected
func TestValidToken(t *testing.T) {
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
	var magic_string string

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	magic_string += "I'm evil"

	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err == nil {
		t.Error("Failed to recognize token was not valid")
		return
	}
	t.Log("got error", err)
}

//Tests that a user can not steal token and gain access to file
func TestInterceptShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	_, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err := InitUser("jane", "fubar1")
	if err != nil {
		t.Error("Failed to initialize jane", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	var magic_string string

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u3.ReceiveFile("file2", "alice", magic_string)
	if err == nil {
		t.Error("Failed to recognize that user stole token", err)
		return
	}
	t.Log("got error", err)
}

//Test's that able to confirm that token was sent from the right person
func TestVerifySender(t *testing.T) {
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
	_, err = InitUser("jane", "fubar1")
	if err != nil {
		t.Error("Failed to initialize jane", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	var magic_string string

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u2.ReceiveFile("file2", "jane", magic_string)
	if err == nil {
		t.Error("Failed to recognize that user was not sender of token", err)
		return
	}
	t.Log("got error", err)
}

//Tests that receive file with name that already exists triggers an error
//also ensures multiple instances of user still have access to shared file
func TestReceive_FileName(t *testing.T) {
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
	u3, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	var magic_string string

	v2 := []byte("happy, now SAD!")
	u2.StoreFile("file2", v2)

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err == nil {
		t.Error("Failed to recognize file already exists under user")
		return
	}
	t.Log("got error", err)
	err = u2.ReceiveFile("file3", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive file")
		return
	}
	v3, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to load shared file from other instance of user")
		return
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("loaded data not same as shared file", string(v), string(v3))
		return
	}
}

//Test that makes sure don't try to share with user that doesnt exist
func TestShareExist(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	_, err = u.ShareFile("file1", "bob")
	if err == nil {
		t.Error("Attempted to share file with user that doesn't exist")
		return
	}
	t.Log("got error", err)
}

//Tests that Revoke successfully revokes access to target
//and all of its children
func TestRevoke(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	u2, err := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return
	}
	u3, err := InitUser("jane", "fubar1")
	if err != nil {
		t.Error("Failed to initialize jane", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	var magic_string string

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file1", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message for bob", err)
		return
	}

	magic_string, err = u2.ShareFile("file2", "jane")
	if err != nil {
		t.Error("Failed to share the file2", err)
		return
	}

	err = u3.ReceiveFile("file3", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message for jane", err)
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke file", err)
		return
	}

	_, err = u3.LoadFile("file3")
	if err == nil {
		t.Error("Revoked child was able to load file")
		return
	}
	t.Log("Received error:", err)
}
