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

func addUser2Datastore(userdata *User) (err error) {
	UUID, HMACKey, SymKey, err := getUserKeys(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	data, err := json.Marshal(userdata)
	if err != nil {
		return err
	}

	err = add2Datastore(UUID, HMACKey, SymKey, data)
	if err != nil {
		return err
	}

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
func getFile(UUID uuid.UUID, HMACKey []byte, SymKey []byte) (file File, data []byte, err error) {
	var filedata [][]byte

	EncData, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return file, data, errors.New("Data not found!")
	}

	EncData, err = verify(EncData, HMACKey)
	if err != nil {
		return file, data, err
	}

	err = json.Unmarshal(EncData, &filedata)
	if err != nil {
		return file, data, err
	}

	DecFile := userlib.SymDec(SymKey, filedata[1])
	depadFile := dePadData(DecFile)
	err = json.Unmarshal(depadFile, &file)
	if err != nil {
		return file, data, err
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
//if it is a shared file, also returns true
func Exists(Map map[string][][]byte, filename string) (entry [][]byte) {
	if val, exists := Map[filename]; exists {
		return val
	}
	return nil
}

func decAndVerify (UUID uuid.UUID, HMACKey []byte, SymKey []byte) (data []byte, err error) {
	data, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return data, errors.New("Data not found!")
	}

	data, err = verify(data, HMACKey)
	if err != nil {
		return data, err
	}

	DecData := userlib.SymDec(SymKey, data)
	data = dePadData(DecData)

	return data, nil
}

func removeAppendedData(metadata [][]byte) (err error) {
	UUID := bytesToUUID(metadata[0])
	data, err := decAndVerify(UUID, metadata[1], metadata[2])
	userlib.DatastoreDelete(UUID)
	if err != nil {
		return err
	}

	var appendedEntries map[int][][]byte
	err = json.Unmarshal(data, &appendedEntries)
	if err != nil {
		return err
	}

	for i := 0; i < len(appendedEntries); i++ {
		entry := appendedEntries[i]
		_, err = decAndVerify(bytesToUUID(entry[0]), entry[1], entry[2])
		userlib.DatastoreDelete(UUID)
		if err != nil {
			return err
		}
	}

	return nil
}

func appendData(metadata [][]byte, data []byte) (appendedData []byte, err error) {
	UUID := bytesToUUID(metadata[0])
	appended, err := decAndVerify(UUID, metadata[1], metadata[2])
	if err != nil {
		return nil, err
	}

	var appendedEntries map[int][][]byte
	err = json.Unmarshal(appended, &appendedEntries)
	if err != nil {
		return nil, err
	}

	appendedData = data
	for i := 0; i < len(appendedEntries); i++ {
		entry := appendedEntries[i]
		ap, err := decAndVerify(bytesToUUID(entry[0]), entry[1], entry[2])
		if err != nil {
			return nil, err
		}
		for j := 0; j < len(ap); j ++ {
			appendedData = append(appendedData, ap[j])
		}
	}

	return appendedData, nil
}

func getMap(arr [][]byte) (dsmap map[string][][]byte, err error) {
	Map, err := decAndVerify(bytesToUUID(arr[0]), arr[1], arr[2])
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(Map, &dsmap)
	if err != nil {
		return nil, err
	}
	return dsmap, nil
}

func getAppendedMap(UUID uuid.UUID, HMACKey []byte, SymKey []byte) (appmap map[uuid.UUID][][]byte, err error) {
	App, err := decAndVerify(UUID, HMACKey, SymKey)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(App, &appmap)
	if err != nil {
		return nil, err
	}
	return appmap, nil
}

func getShared(UUID uuid.UUID, HMACKey []byte, SymKey []byte) (share Share, err error) {
	sharedata, err := decAndVerify(UUID, HMACKey, SymKey)
	if err != nil {
		return share, err
	}

	err = json.Unmarshal(sharedata, &share)
	if err != nil {
		return share, err
	}
	return share, nil
}

func sharedOrExists(userdata *User, filename string) (mapEntry [][]byte, Map map[string][][]byte, shared bool, err error) {
	Map, err = getMap(userdata.Files)
	if err != nil {
		return nil, Map,false, err
	}

	mapEntry = Exists(Map, filename)
	shared = false
	if mapEntry == nil {
		Map, err = getMap(userdata.SharedFiles)
		if err != nil {
			return nil, Map, false, err
		}
		mapEntry = Exists(Map, filename)
		shared = true
	}
	return mapEntry, Map, shared, nil
}

func getShareKeys(UUID uuid.UUID, name string) (HMACKey []byte, SymKey []byte, err error) {
	salt := userlib.Hash([]byte(name))
	var bsalt []byte = salt[:]
	RootKey := userlib.Argon2Key(uuidToBytes(UUID), bsalt, 16)
	HMACKey, err = userlib.HashKDF(RootKey, []byte("share hmac key"))
	SymKey, err = userlib.HashKDF(RootKey, []byte("share sym key"))
	if err != nil {
		return nil, nil, err
	}
	return HMACKey[:16], SymKey[:16], nil
}


// //initializes a Share struct for the recipient and returns the UUID and RSA decryption key of
// //the Share struct in order to generate the access token
func initShare(mapEntry [][]byte, ApEntry [][]byte, recipient string) (UUID uuid.UUID, err error) {
	var fileShare Share
	UUID = uuid.New()
	fileShare.HMACKeyFile = mapEntry[1]
	fileShare.UUIDFile = bytesToUUID(mapEntry[0])
	fileShare.SymKeyFile = mapEntry[2]
	fileShare.AppendedData = ApEntry

	HMACKey, SymKey, err := getShareKeys(UUID, recipient)
	if err != nil {
		return UUID, err
	}

	//add Share struct to Datastore
	data, err := json.Marshal(fileShare)
	if err != nil {
		return UUID, err
	}

	err = add2Datastore(UUID, HMACKey, SymKey, data)
	if err != nil {
		return UUID, err
	}
	return UUID, nil
}

func isChild(ShareTree map[string][][]byte, username string, target string) (UUID uuid.UUID, err error) {
	entry := ShareTree[target]
	if entry == nil{
		return UUID, errors.New("User has not shared file")
	}
	entry_name := string(entry[0])
	if entry_name != username {
		return UUID, errors.New("User has not shared file with target")
	}
	return bytesToUUID(entry[1]), nil
}

func DeleteChildren(ShareTree map[string][][]byte, target string) (tree map[string][][]byte){
	loopTree := ShareTree
	i := 0
	for child, parent := range loopTree {
		sharer := string(parent[0])
		if sharer == target {
			UUID := bytesToUUID(parent[1])
			userlib.DatastoreDelete(UUID)
			delete(ShareTree, child)
			ShareTree = DeleteChildren(ShareTree, child)
			i++
		}
	}
	return ShareTree
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	SignKey userlib.DSSignKey
	RSADecKey userlib.PKEDecKey
	Files [][]byte
	SharedFiles [][]byte
	AppendedData [][]byte
}

//file record
type File struct {
	Username string
	ShareTree map[string][][]byte
}

//a record of a shared file between 2 users 
type Share struct {
	UUIDFile uuid.UUID
	SymKeyFile []byte
	HMACKeyFile []byte
	AppendedData [][]byte
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

	FilesUUID := uuid.New()
	FilesHmac, FilesSym := genFileKeys()
	SharedUUID := uuid.New()
	SharedHmac, SharedSym := genFileKeys()
	AppendUUID := uuid.New()
	AppendHmac, AppendSym := genFileKeys()

	userdata.Files = [][]byte{uuidToBytes(FilesUUID), FilesHmac, FilesSym}
	userdata.SharedFiles = [][]byte{uuidToBytes(SharedUUID), SharedHmac, SharedSym}
	userdata.AppendedData = [][]byte{uuidToBytes(AppendUUID), AppendHmac, AppendSym}

	Files := make(map[string][][]byte)
	Shared := make(map[string][][]byte)
	Appended := make(map[uuid.UUID][][]byte)

	mFiles, err := json.Marshal(Files)
	mShared, err := json.Marshal(Shared)
	mAppended, err := json.Marshal(Appended)
	if err != nil {
		return nil, err
	}

	err = add2Datastore(FilesUUID, FilesHmac, FilesSym, mFiles)
	err =add2Datastore(SharedUUID, SharedHmac, SharedSym, mShared)
	err = add2Datastore(AppendUUID, AppendHmac, AppendSym, mAppended)
	if err != nil {
		return nil, err
	}

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

	err = addUser2Datastore(&userdata)
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

	data, err := decAndVerify(UUID, HMACKey, SymKey)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, userdataptr)
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
	mapEntry, Map, shared, err := sharedOrExists(userdata, filename)
	if err != nil {
		return
	}

	if mapEntry != nil {
		UUID := bytesToUUID(mapEntry[0])
		HMACKey := mapEntry[1]
		SymKey := mapEntry[2]

		ApUUID := bytesToUUID(userdata.AppendedData[0])
		ApHMAC := userdata.AppendedData[1]
		ApSym := userdata.AppendedData[2]

		if shared {
			share, err := getShared(UUID, HMACKey, SymKey)
			if err != nil {
				return
			}
			ApUUID = bytesToUUID(share.AppendedData[0])
			ApHMAC = share.AppendedData[1]
			ApSym = share.AppendedData[2]

			UUID = share.UUIDFile
			HMACKey = share.HMACKeyFile
			SymKey = share.SymKeyFile
		}

		apmap, err := getAppendedMap(ApUUID, ApHMAC, ApSym)
		if err != nil {
			return
		}

		appendedMeta := apmap[UUID]
		if appendedMeta != nil {
			err := removeAppendedData(appendedMeta)
			if err != nil {
				HMACKey, SymKey = genFileKeys()
			}
			delete(apmap, UUID)
			apdata, _ := json.Marshal(apmap)
			err = add2Datastore(ApUUID, ApHMAC, ApSym, apdata)
			if err != nil {
				return
			}
		}

		file, ok := userlib.DatastoreGet(UUID)
		if !ok {
			return 
		}

		file, err = verify(file, HMACKey)
		if err != nil {
			HMACKey, SymKey = genFileKeys()
		}

		var filedata [][]byte
		_ = json.Unmarshal(file, &filedata)
		DecFile := userlib.SymDec(SymKey, filedata[1])
		depadFile := dePadData(DecFile)

		addFile2Datastore(UUID, HMACKey, SymKey, depadFile, data)

	} else {
		var userfile File
		userfile.Username = userdata.Username
		userfile.ShareTree = make(map[string][][]byte)
		UUID := uuid.New()
		HMACKey, SymKey := genFileKeys()

		Map[filename] = [][]byte{uuidToBytes(UUID), HMACKey, SymKey}
		file, _ := json.Marshal(userfile)
		mfilemap, _ := json.Marshal(Map)
		_ = add2Datastore(bytesToUUID(userdata.Files[0]), userdata.Files[1], userdata.Files[2], mfilemap)
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
	mapEntry, _, shared, err := sharedOrExists(userdata, filename)
	if err != nil {
		return
	} else if mapEntry == nil {
		return errors.New(strings.ToTitle("filename does not exist under user"))
	}
	UUID := bytesToUUID(mapEntry[0])

	ApUUID := bytesToUUID(userdata.AppendedData[0])
	ApHMAC := userdata.AppendedData[1]
	ApSym := userdata.AppendedData[2]

	if shared {
		HMACKey := mapEntry[1]
		SymKey := mapEntry[2]
		share, err := getShared(UUID, HMACKey, SymKey)
		if err != nil {
			return err
		}
		ApUUID = bytesToUUID(share.AppendedData[0])
		ApHMAC = share.AppendedData[1]
		ApSym = share.AppendedData[2]

		UUID = share.UUIDFile
		HMACKey = share.HMACKeyFile
		SymKey = share.SymKeyFile
	}

	apmap, err := getAppendedMap(ApUUID, ApHMAC, ApSym)
	if err != nil {
		return err
	}

	entry := apmap[UUID]
	if entry == nil {
		MapUUID := uuid.New()
		MapHMACKey, MapSymKey := genFileKeys()

		apmap[UUID] = [][]byte{uuidToBytes(MapUUID), MapHMACKey, MapSymKey}
		appendedEntries := make(map[int][][]byte)
		NewUUID := uuid.New()
		NewHMACKey, NewSymKey := genFileKeys()
		appendedEntries[0] = [][]byte{uuidToBytes(NewUUID), NewHMACKey, NewSymKey}
		mEntries, err := json.Marshal(appendedEntries)
		if err != nil {
			return err
		}
		err = add2Datastore(MapUUID, MapHMACKey, MapSymKey, mEntries)
		if err != nil {
			return err
		}

		err = add2Datastore(NewUUID, NewHMACKey, NewSymKey, data)
		if err != nil {
			return err
		}

		m_apmap, _ := json.Marshal(apmap)
		_ = add2Datastore(ApUUID, ApHMAC, ApSym, m_apmap)
		return nil
	}

	UUIDmap := bytesToUUID(entry[0])
	HMACKeymap := entry[1]
	SymKeymap := entry[2]
	entries, err := decAndVerify(UUIDmap, HMACKeymap, SymKeymap)
	if err != nil {
		return err
	}
	var appendedEntries map[int][][]byte
	err = json.Unmarshal(entries, &appendedEntries)
	if err != nil {
		return err
	}

	NewUUID := uuid.New()
	NewHMACKey, NewSymKey := genFileKeys()
	appendedEntries[len(appendedEntries)] = [][]byte{uuidToBytes(NewUUID), NewHMACKey, NewSymKey}
	mentries, _ := json.Marshal(appendedEntries)
	_ = add2Datastore(UUIDmap, HMACKeymap, SymKeymap, mentries)
	err = add2Datastore(NewUUID, NewHMACKey, NewSymKey, data)
	return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	mapEntry, _, shared, err := sharedOrExists(userdata, filename)
	if err != nil {
		return
	} else if mapEntry == nil {
		return nil, errors.New(strings.ToTitle("filename does not exist under user"))
	}
		UUID := bytesToUUID(mapEntry[0])
		HMACKey := mapEntry[1]
		SymKey := mapEntry[2]

		ApUUID := bytesToUUID(userdata.AppendedData[0])
		ApHMAC := userdata.AppendedData[1]
		ApSym := userdata.AppendedData[2]

		if shared {
			share, err := getShared(UUID, HMACKey, SymKey)
			if err != nil {
				return nil, err
			}
			ApUUID = bytesToUUID(share.AppendedData[0])
			ApHMAC = share.AppendedData[1]
			ApSym = share.AppendedData[2]

			UUID = share.UUIDFile
			HMACKey = share.HMACKeyFile
			SymKey = share.SymKeyFile
		}

	_, filedata, err := getFile(UUID, HMACKey, SymKey)
	if err != nil {
		return nil, err
	}

	apmap, err := getAppendedMap(ApUUID, ApHMAC, ApSym)
	if err != nil {
		return data, err
	}

	appendedMeta := apmap[UUID]
	if appendedMeta != nil {
		filedata, err = appendData(appendedMeta, filedata)
		if err != nil {
			return nil, err
		}
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
	mapEntry, _, shared, err := sharedOrExists(userdata, filename)
	if err != nil {
		return
	} else if mapEntry == nil {
		return magic_string, errors.New(strings.ToTitle("filename does not exist under user"))
	}
	tokenEncKey, ok := userlib.KeystoreGet(recipient + "RSA")
	if !ok {
		return magic_string, errors.New(strings.Title("recipient's username doesn't exist"))
	}

		UUID := bytesToUUID(mapEntry[0])
		HMACKey := mapEntry[1]
		SymKey := mapEntry[2]
		AppendedData := userdata.AppendedData

	if shared {
		share, err := getShared(UUID, HMACKey, SymKey)
		if err != nil {
			return magic_string, err
		}

		UUID = share.UUIDFile
		HMACKey = share.HMACKeyFile
		SymKey = share.SymKeyFile
		AppendedData = share.AppendedData
	}

	file, filedata, err := getFile(UUID, HMACKey, SymKey)
	if err != nil {
		return magic_string, err
	}

	//generate Share struct
	ShareUUID, err := initShare(mapEntry, AppendedData, recipient)
	if err != nil {
		return magic_string, err
	}

	//add share mapping to file
	if file.ShareTree[recipient] != nil {
		return magic_string, errors.New("file has already been shared with recipient")
	}
	file.ShareTree[recipient] = [][]byte{[]byte(userdata.Username), uuidToBytes(ShareUUID)}
	mfile, err := json.Marshal(file)
	if err != nil {
		return magic_string, err
	}
	addFile2Datastore(UUID, HMACKey, SymKey, mfile, filedata)

	//generate token
	mtoken, err := json.Marshal(ShareUUID)
	if err != nil {
		return magic_string, err
	}

	EncToken, err := userlib.PKEEnc(tokenEncKey, mtoken)
	if err != nil {
		return magic_string, err
	}

	signature, err := userlib.DSSign(userdata.SignKey, EncToken)
	if err != nil {
		return magic_string, err
	}

	Package := [][]byte{EncToken, signature}
	mPackage, err := json.Marshal(Package)
	if err != nil {
		return magic_string, err
	}

	return string(mPackage), nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	mapEntry, _, _, err := sharedOrExists(userdata, filename)
	if err != nil {
		return err
	} else if mapEntry != nil {
		return errors.New(strings.ToTitle("filename already exist under user"))
	}

	//extract Share UUID from token
	VerifyKey, ok := userlib.KeystoreGet(sender)
	if !ok {
		return errors.New("sender verification key not found")
	}

	var mtoken [][]byte
	err = json.Unmarshal([]byte(magic_string), &mtoken)
	if err != nil {
		return err
	}

	err = userlib.DSVerify(VerifyKey, mtoken[0], mtoken[1])
	if err != nil {
		return err
	}

	ShareUUID, err := userlib.PKEDec(userdata.RSADecKey, mtoken[0])
	if err != nil {
		return err
	}

	HMACKey, SymKey, err := getShareKeys(bytesToUUID(ShareUUID), userdata.Username)
	if err != nil {
		return err
	}

	metadata, err := decAndVerify(bytesToUUID(userdata.SharedFiles[0]), userdata.SharedFiles[1], userdata.SharedFiles[2])
	var sharemap map[string][][]byte
	err = json.Unmarshal(metadata, &sharemap)
	if err != nil {
		return err
	}

	sharemap[filename] = [][]byte{ShareUUID, HMACKey, SymKey}
	msharemap, _ := json.Marshal(sharemap)
	err = add2Datastore(bytesToUUID(userdata.SharedFiles[0]), userdata.SharedFiles[1], userdata.SharedFiles[2], msharemap)

	return err
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	mapEntry, _, shared, err := sharedOrExists(userdata, filename)
	if err != nil {
		return
	} else if mapEntry == nil {
		return errors.New(strings.ToTitle("filename does not exist under user"))
	}
	UUID := bytesToUUID(mapEntry[0])
	HMACKey := mapEntry[1]
	SymKey := mapEntry[2]

	if shared {
		share, err := getShared(UUID, HMACKey, SymKey)
		if err != nil {
			return  err
		}
		UUID = share.UUIDFile
		HMACKey = share.HMACKeyFile
		SymKey = share.SymKeyFile
	}

	file, filedata, err := getFile(UUID, HMACKey, SymKey)
	if err != nil {
		return err
	}

	ShareUUID, err := isChild(file.ShareTree, userdata.Username, target_username)
	if err != nil {
		return err
	}
	delete(file.ShareTree, userdata.Username)
	userlib.DatastoreDelete(ShareUUID)
	file.ShareTree = DeleteChildren(file.ShareTree, target_username)

	mFile, err := json.Marshal(file)
	if err != nil {
		return err
	}
	addFile2Datastore(UUID, HMACKey, SymKey, mFile, filedata)
	return nil
}
