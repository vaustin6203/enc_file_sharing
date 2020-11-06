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
	//for x := range ret {
		//ret[x] = data[x]
	//}
	json.Unmarshal(data, &ret)
	return ret
}

// Helper function: Takes UUID and convertes to []byte
func uuidToBytes(UUID uuid.UUID) (ret []byte) {
	ret, _ = json.Marshal(UUID)
	return ret
}

//Helper function: generates an HMAC key and symmetric key from a random number
func genFileKeys()(HMACKey []byte, SymKey []byte) {
	RootKey := userlib.RandomBytes(16)
	HMACKey, _ = userlib.HashKDF(RootKey, []byte("file hmac key"))
	SymKey, _ = userlib.HashKDF(RootKey, []byte("file sym key"))
	return HMACKey[:16], SymKey[:16]
}

//Helper function: given a user's password and username,
//returns the UUID, HMACKey, and Symmetric Key of the user
func getUserKeys(password string, username string) (UUID uuid.UUID, 
	HMACKey []byte, SymKey []byte, err error) {
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

//Helper function: removes padding from decrypted data
//retreived from Datastore
func dePadData(data []byte) (unPaddedData []byte) {
	length := len(data)
	last := int(data[length -1])
	unPaddedData = data[:length - last]
	return unPaddedData
}

//Helper function: adds data to DataStore that uses symetric encryption
//Note: data arg must already be marshalled 
func add2Datastore(UUID uuid.UUID, HMACKey []byte, SymKey []byte, 
	data []byte) (err error) {
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

//Helper function: adds data to DataStore that uses asymetric encryption
//Note: data arg must already be marshalled 
func addFile2Datastore(UUID uuid.UUID, HMACKey []byte, 
	SymKey []byte, file []byte, data []byte) {
	iv1 := userlib.RandomBytes(userlib.AESBlockSize)
	PaddedFile := padData(file)
	iv2 := userlib.RandomBytes(userlib.AESBlockSize)
	PaddedData := padData(data)
	EncFile := userlib.SymEnc(SymKey, iv1, PaddedFile)
	EncData := userlib.SymEnc(SymKey, iv2, PaddedData)

	DataFile := [][]byte{EncData, EncFile}
	mDataFile, _ := json.Marshal(DataFile)

	mac, _ := userlib.HMACEval(HMACKey, mDataFile)

	Package := [][]byte{mDataFile, mac}
	mPackage, _ := json.Marshal(Package)

	userlib.DatastoreSet(UUID, mPackage)

	return
}

//Helper function: given a user's mapEntry of a file, retreives, verfies, 
//& decrypts file and its data
//returns error if error occurs 
func getFile(mapEntry [][]byte) (file File, data []byte, err error) {
	var filedata [][]byte
	UUID := bytesToUUID(mapEntry[0])
	HMACKey := mapEntry[1]
	SymKey := mapEntry[2]

	data, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return file, nil, errors.New(strings.ToTitle("File not found!"))
	}

	EncData, err := verify(data, HMACKey)
	if err != nil {
		return file, nil, err
	}

	err = json.Unmarshal(EncData, &filedata)
	if err != nil {
		return file, nil, err
	}

	DecFile := userlib.SymDec(SymKey, filedata[1])
	depadFile := dePadData(DecFile)
	err = json.Unmarshal(depadFile, &file)
	if err != nil {
		return file, nil, err
	}

	DecData := userlib.SymDec(SymKey, filedata[0])
	depadData := dePadData(DecData)
	return file, depadData, nil
}

//Helper function: verifies integrity of data loaded from Datastore
//returns false if data has been tampered with
func checkIntegrity(data []byte, mac []byte, HMACKey []byte) (ok bool) {
	VerifyMAC, _ := userlib.HMACEval(HMACKey, data)
	return userlib.HMACEqual(mac, VerifyMAC)
}

//Helper function: for a marshalled {EncData, mac}, verifies the integrity 
//of the encrypted data and returns it 
func verify(data []byte, HMACKey []byte) (verfied_data []byte, err error) {
	var Package [][]byte 
	err = json.Unmarshal(data, &Package)
	if err != nil {
		return nil, err
	}

	if !checkIntegrity(Package[0], Package[1], HMACKey) {
		return nil, errors.New("unable to verify integrity of user data")
	}

	return Package[0], nil
}

//Helper function: determines if a filename already exists for a user
//return map entry under filename if exists and nil otherwise 
func sharedOrExists(filemap map[string][][]byte, shared_filemap map[string][][]byte, 
	filename string) (entry [][]byte) {
	if val, exists := filemap[filename]; exists {
		return val
	} else if val, exists = shared_filemap[filename]; exists {
		return val
	}
	return nil
}

//Helper function: appends new data to the end of a file 
func appendData(data2append []byte, data []byte) (appendedData []byte) {
	dataLength := len(data2append)
	appendedData = data

	for i := 0; i < dataLength; i++ {
		appendedData = append(appendedData, data2append[i])
	}

	return appendedData
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	SignKey userlib.DSSignKey
	RSADecKey userlib.PKEDecKey
	Files map[string][][]byte 
	SharedFiles map[string][][]byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

//file record
type File struct {
	Username string
	ShareTree map[string][][]byte
}


//a record of a shared file between 2 users 
type Share struct {
	UUID uuid.UUID
	RSADecKey userlib.PKEDecKey
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
	userdata.Files = make(map[string][][]byte)
	userdata.SharedFiles = make(map[string][][]byte)

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
	if err != nil {
		return nil, err
	}

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	UUID, HMACKey, SymKey, err := getUserKeys(username, password)
	if err != nil {
		return nil, err
	}

	data, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, errors.New("user does not exist")
	}

	EncData, err := verify(data, HMACKey)
	if err != nil {
		return nil, err
	}

	DecData := userlib.SymDec(SymKey, EncData)
	unPaddedData := dePadData(DecData)
	err = json.Unmarshal(unPaddedData, userdataptr)
	if err != nil {
		return nil, err
	}

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	mapEntry := sharedOrExists(userdata.Files, userdata.SharedFiles, filename)
	if mapEntry != nil {

		//If data has lossed integrity, change HMACKey so LoadFile
		//will detect the loss later 
		UUID := bytesToUUID(mapEntry[0])
		HMACKey := mapEntry[1]
		SymKey := mapEntry[2]

		file, _ := userlib.DatastoreGet(UUID)
		EncData, err := verify(file, HMACKey)
		if err != nil {
			HMACKey, SymKey = genFileKeys()
			
		}

		var filedata [][]byte
		_ = json.Unmarshal(EncData, &filedata)
		DecFile := userlib.SymDec(SymKey, filedata[1])
		depadFile := dePadData(DecFile)

		if err != nil {
			HMACKey, SymKey = genFileKeys()
			
		}

		addFile2Datastore(UUID, HMACKey, SymKey, depadFile, data)
	} else {
		var userfile File
		userfile.Username = userdata.Username
		userfile.ShareTree = make(map[string][][]byte)
		UUID := uuid.New()
		HMACKey, SymKey := genFileKeys()

		userdata.Files[filename] = [][]byte{uuidToBytes(UUID), HMACKey, SymKey}
		file, _ := json.Marshal(userfile)

		addFile2Datastore(UUID, HMACKey, SymKey, file, data)
	}

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// mapEntry := sharedOrExists(userdata.Files, userdata.SharedFiles, filename)
	// if mapEntry == nil {
	// 	return errors.New(strings.ToTitle("filename does not exist under user"))
	// }

	// var filedata File
	// UUID := bytesToUUID(mapEntry[0])
	// HMACKey := mapEntry[1]
	// SymKey := mapEntry[2]

	// data, ok := userlib.DatastoreGet(UUID)
	// if !ok {
	// 	return filedata, errors.New(strings.ToTitle("File not found!"))
	// }

	// EncData, err := verify(data, HMACKey)
	// if err != nil {
	// 	return filedata, err
	// }

	// appendedData := appendData(data, )
	
	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	mapEntry := sharedOrExists(userdata.Files, userdata.SharedFiles, filename)
	if mapEntry == nil {
		return nil, errors.New(strings.ToTitle("filename does not exist under user"))
	}

	_, filedata, err := getFile(mapEntry)
	if err != nil {
		return nil, err
	}
	return filedata, nil
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
