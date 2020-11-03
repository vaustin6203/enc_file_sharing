package proj2

// CS 161 Project 2 Fall 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//Helper function: given a user's password and username,
//returns the UUID, HMACKey, and Symmetric Key of the user
func getUserKeys(password string, username string) (UUID uuid.UUID, HMACKey []byte, SymKey []byte, err error) {
	salt := userlib.Hash([]byte(username))
	var bsalt []byte = salt[:]

	RootKey := userlib.Argon2Key([]byte(password), bsalt, 16)
	UUID, err = uuid.FromBytes(RootKey)

	HMACKey, err = userlib.HashKDF(RootKey, []byte("user hmac key"))
	if err != nil {
		return UUID, nil, nil, err
	}

	SymKey, err = userlib.HashKDF(RootKey, []byte("user sym key"))
	if err != nil {
		return UUID, nil, nil, err
	}

	return UUID, HMACKey[:16], SymKey[:16], nil
}

//Helper function: returns true if username already exists 
func userExists(username string) (exists bool) {
	_, exists = userlib.KeystoreGet(username)
	return exists
}

//Helper function: pads data for sym cryptography 
//uses method decribed in lecture (slide 25)
//returns the length/value that the data was padded with
//source: https://cs161.org/assets/lectures/lec06.pdf
func padData(data []byte) (PaddedData []byte){
	r := userlib.AESBlockSize - (len(data) % userlib.AESBlockSize)
	pad := byte(r)
	PaddedData = data

	//if size is equal to zero, pad a full block with 0
	if r == 0 {
		r = userlib.AESBlockSize
	}

	for i := 0; i < r; i++ {
		PaddedData = append(PaddedData, pad)
	}

	return PaddedData
}

//Helper function: adds data to DataStore
//Note: data arg must already be marshalled 
func add2Datastore(UUID uuid.UUID, HMACKey []byte, SymKey []byte, data []byte) (err error) {
	iv := userlib.RandomBytes(userlib.AESBlockSize)
	PaddedData := padData(data)
	EncData := userlib.SymEnc(SymKey, iv, PaddedData)

	mac, err := userlib.HMACEval(HMACKey, EncData)
	if err != nil {
		return err
	}

	Package := [][]byte{EncData, mac}
	mPackage, err := json.Marshal(Package)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(UUID, mPackage)

	return nil
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	SignKey userlib.DSSignKey
	RSADecKey userlib.PKEDecKey
	Files map[string][]byte 
	SharedFiles map[string][]byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

//file record
type File struct {
	Username string
	ShareTree map[string][]byte
}


//a record of a shared file between 2 users 
type Share struct {
	UUID uuid.UUID
	RSADecKey userlib.PKEDecKey
	HMACKey []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	if userExists(username) {
		return nil, errors.New("username already exists")
	}

	var userdata User
	userdataptr = &userdata

	userdata.Username = username
	userdata.Password = password

	SignKey, VerifyKey, err := userlib.DSKeyGen()
	userdata.SignKey = SignKey
	err = userlib.KeystoreSet(username, VerifyKey)
	if err != nil {
		return nil, err
	}

	RSAEncKey, RSADecKey, err := userlib.PKEKeyGen()
	userdata.RSADecKey = RSADecKey
	err = userlib.KeystoreSet(username + "RSA", RSAEncKey)
	if err != nil {
		return nil, err
	}

	UUID, HMACKey, SymKey, err := getUserKeys(username, password)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	err = add2Datastore(UUID, HMACKey, SymKey, data)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	//TODO: This is a toy implementation.
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	packaged_data, _ := json.Marshal(data)
	userlib.DatastoreSet(UUID, packaged_data)
	//End of toy implementation

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	//TODO: This is a toy implementation.
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	packaged_data, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(packaged_data, &data)
	return data, nil
	//End of toy implementation

	return
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}