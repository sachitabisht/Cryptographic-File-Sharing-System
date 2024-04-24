package client

// CS 161 Project 2
//TO DO:
//1. secure against Datastore Adversary
//2. secure against Revoked User Adversary
//3. Efficiently append bandwidth
//4. Edge case for revoking before invite is accepted

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username         string
	Password         string
	Salt             []byte
	UserID           uuid.UUID //check if this works
	PrivKey          userlib.PKEDecKey
	FileNames        map[string]uuid.UUID
	FileKeys         map[string][]byte
	HashedPassword   []byte
	SymmetricFileKey []byte
	AccessStructUUID string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type FileNode struct {
	UUID     uuid.UUID
	Content  *ContentPointer
	NextNode *FileNode
}

type ContentPointer struct {
	UUID uuid.UUID
}

var contentMap map[uuid.UUID][]byte

func init() {
	contentMap = make(map[uuid.UUID][]byte)
}

type File struct {
	FileName      string    //potentially hashing?
	Head          *FileNode //first node in list ptr
	Tail          *FileNode //last node in list ptr
	FileKey       []byte    //TO DO: figure out how to call on keys
	NodeCount     int       //# of nodes in list
	HMAC          []byte
	HMACKey       []byte
	Owner         string
	OwnerFileName string
}

type Invitation struct {
	UUID           uuid.UUID
	FileName       string
	SenderUsername string
	OwnerUsername  string
	FileOwnerName  string
	FileKey        []byte
	Accepted       bool
}

type Shared struct {
	UniveralUUID   uuid.UUID //store access struct uuid in owner's user struct
	Username       string    //username
	FileName       string
	Owner          string
	FileKey        []byte
	SharedTo       map[string]*Shared
	RedFlag        map[string][]string
	InvitationPtrs map[string]*Invitation
	EncInvHMAC     []byte
	EncInvHMACKey  []byte
	//NOTE: when revoke, we cut of Shared Struct with username (person revoked)
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) <= 0 {
		return nil, errors.New("Invalid Username. Username lenght must be greater than 0")
	} else {
		//Create UUID from username
		usernameUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + password))[:16])
		if err != nil {
			return nil, errors.New("issue when creating username")
		}
		_, getUsernameID := userlib.DatastoreGet(usernameUUID)
		if getUsernameID {
			return nil, errors.New("This user already exists.")
		}
		var userdata User
		userdata.Username = username
		userdata.Password = password
		userdata.UserID = usernameUUID
		userdata.FileNames = make(map[string]uuid.UUID)
		userdata.FileKeys = make(map[string][]byte)
		userdata.Salt = userlib.Hash([]byte(username + password))
		userdata.HashedPassword = userlib.Argon2Key([]byte(password), userdata.Salt, 16)

		//key generation
		var public_key userlib.PKEEncKey
		var priv_key userlib.PKEDecKey
		public_key, priv_key, err = userlib.PKEKeyGen()

		if err != nil {
			return nil, errors.New("Error occured while generating key")
		}
		//TO DO: find key for encrypting private key- use HashKDF

		userdata.PrivKey = priv_key

		userdata_json, err := json.Marshal(userdata)
		if err != nil {
			return nil, errors.New("Error occured while converting userdata to bytes")
		}

		//encrypt userstruct:
		IV_2 := userlib.RandomBytes(16)
		encryptedkey_userstruct, err := userlib.HashKDF(userdata.HashedPassword, []byte("user struct encryption"))
		if err != nil {
			return nil, errors.New("Error occurred while creating encryption key for user struct")
		}
		encrypted_JSON := userlib.SymEnc(encryptedkey_userstruct[:16], IV_2, userdata_json)
		hmac_user_key := userlib.RandomBytes(16)
		hmac_user, err := userlib.HMACEval(hmac_user_key, encrypted_JSON)
		if err != nil {
			return nil, errors.New("issue hmac-ing user struct")
		}
		hmacUUID, err := uuid.FromBytes(userlib.Hash([]byte("hmacUUID" + username))[:16])
		if err != nil {
			return nil, errors.New("issue when creating username")
		}
		hmacUUID_key, err := uuid.FromBytes(userlib.Hash([]byte("hmacKEYUUID" + username))[:16])
		if err != nil {
			return nil, errors.New("issue when creating username")
		}
		userlib.DatastoreSet(hmacUUID, hmac_user)
		userlib.DatastoreSet(hmacUUID_key, hmac_user_key)
		userlib.DatastoreSet(usernameUUID, encrypted_JSON)
		userlib.KeystoreSet(username+"public", public_key)
		return &userdata, nil
	}

}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	//error if username not existing
	//regenerate UUID (same way as InitUser)
	usernameUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + password))[:16])
	if err != nil {
		return nil, err
	}
	userDataBytes, ok := userlib.DatastoreGet(usernameUUID)
	if !ok {
		return nil, errors.New("Username does not exist.")
	}
	hmacUUID, err := uuid.FromBytes(userlib.Hash([]byte("hmacUUID" + username))[:16])
	if err != nil {
		return nil, errors.New("issue when creating username")
	}
	hmacUUID_key, err := uuid.FromBytes(userlib.Hash([]byte("hmacKEYUUID" + username))[:16])
	if err != nil {
		return nil, errors.New("issue when creating username")
	}
	hmac_key, ok := userlib.DatastoreGet(hmacUUID_key)
	if !ok {
		return nil, errors.New("issue getting hmac key")
	}
	hmac_user, ok := userlib.DatastoreGet(hmacUUID)
	if !ok {
		return nil, errors.New("issue getting hmac key")
	}
	hmac_get_user, err := userlib.HMACEval(hmac_key, userDataBytes)
	if err != nil {
		return nil, errors.New("issue hmac-ing user struct")
	}

	ok = userlib.HMACEqual(hmac_get_user, hmac_user)
	if !ok {
		return nil, errors.New("user struct has been tampered with")
	}
	//make hashed password
	decryptedkey_userstruct_check := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username+password)), 16)
	decryptedkey_userstruct, err := userlib.HashKDF(decryptedkey_userstruct_check, []byte("user struct encryption"))
	if err != nil {
		return nil, errors.New("Error occurred while creating decryption key for user struct")
	}
	//decrypt userstruct
	decrypted_JSON := userlib.SymDec(decryptedkey_userstruct[:16], userDataBytes)
	if decrypted_JSON == nil {
		return nil, errors.New("issue when decrypting")
	}
	//unmarshal

	err = json.Unmarshal(decrypted_JSON, &userdata)
	if err != nil {
		return nil, errors.New("Error while unmarshalling userdata")
	}
	//compare
	if len(decryptedkey_userstruct_check) != len(userdata.HashedPassword) {
		return nil, errors.New("Unable to login")
	}

	for i := range decryptedkey_userstruct_check {
		if decryptedkey_userstruct_check[i] != userdata.HashedPassword[i] {
			return nil, errors.New("Unable to login")
		}
	}

	//error if password is wrong
	if password != userdata.Password {
		return nil, errors.New("Password is incorrect.")
	}

	return userdataptr, nil

}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//TODO!!!!: make storage key secure
	//if she is RESTORING --> check for tampering
	fileUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	dataJSON, ok := userlib.DatastoreGet(fileUUID)
	if ok {
		var shared Shared
		shared_bytes := []byte(userdata.Username + "shared")
		hashed_shared_bytes := userlib.Hash(shared_bytes)
		shared_uuid, err := uuid.FromBytes(hashed_shared_bytes[:16])
		if err != nil {
			return errors.New("3. error converting to UUID")
		}
		shared_struct, ok := userlib.DatastoreGet(shared_uuid)
		if !ok {
			return errors.New("3. error getting shared struct")
		}
		err = json.Unmarshal(shared_struct, &shared)
		if err != nil {
			return errors.New("issue unmarshalling shared struct")
		}
		decryptedkey_filestruct_check := shared.FileKey

		//decryptedkey_filestruct_check := userlib.Argon2Key([]byte(userdata.Password), userlib.Hash([]byte(userdata.Username+userdata.Password)), 16)
		decryptedkey_filestruct, err := userlib.HashKDF(decryptedkey_filestruct_check, []byte("file struct encryption"))
		if err != nil {
			return errors.New("Error occurred while creating decryption key for user struct")
		}
		decryptedFileData := userlib.SymDec(decryptedkey_filestruct[:16], dataJSON)
		if decryptedFileData == nil {
			return errors.New("issue when decrypting")
		}

		var file File
		err = json.Unmarshal(decryptedFileData, &file)
		if err != nil {
			return errors.New("!!!issue unmarshalling file struct")
		}

	}
	owner_filename := filename
	fileUUID, err = uuid.FromBytes(userlib.Hash([]byte(owner_filename + userdata.Username))[:16])
	if err != nil {
		return errors.New("issue when creating storage key")
	}
	//create new file encryption key
	fileEncryptionKey := userlib.RandomBytes(16)
	if fileEncryptionKey == nil {
		return errors.New("issue with making file key")
	}

	//1. encrpt symmetric key with public key
	//2. Encrypt file struct with symmetric key
	//3. Decrypt summetric key with provate key
	//4. the decrytped symmetric key will decryt the file struct

	//update file map
	userdata.FileNames[filename] = fileUUID
	//create new filestruct with pointers

	var file File
	file = File{
		FileName:      filename,
		Head:          nil,
		Tail:          nil,
		FileKey:       fileEncryptionKey,
		NodeCount:     0,
		HMAC:          nil,
		HMACKey:       nil,
		Owner:         userdata.Username,
		OwnerFileName: owner_filename,
	}

	newContentUUID := uuid.New()
	newContentPointer := &ContentPointer{
		UUID: newContentUUID,
	}

	newNode := &FileNode{
		UUID:     uuid.New(),
		Content:  newContentPointer,
		NextNode: nil,
	}

	IV := userlib.RandomBytes(16)
	newNode.Content.UUID = newContentUUID
	// Store the actual content in a separate map
	contentMap[newContentUUID] = userlib.SymEnc(file.FileKey, IV, content)
	// Add node to the linked list
	if file.Head == nil {
		file.Head = newNode
		file.Tail = nil
	} else {
		file.Tail.NextNode = newNode
		file.Tail = newNode
	}
	file.NodeCount++

	var shared Shared
	emptyShared := make(map[string]*Shared)
	emptyRedFlag := make(map[string][]string)
	emptyInv := make(map[string]*Invitation)
	shared = Shared{
		UniveralUUID:   fileUUID,          //store access struct uuid in owner's user struct
		Username:       userdata.Username, //username
		FileName:       filename,
		Owner:          userdata.Username,
		FileKey:        fileEncryptionKey,
		SharedTo:       emptyShared,
		RedFlag:        emptyRedFlag,
		InvitationPtrs: emptyInv,
	}
	//TO DO: 1. update filenames and filekeys map with new filename/file key
	currentNode := file.Head
	contentData := contentMap[currentNode.Content.UUID]
	hmacKey := userlib.RandomBytes(16)
	hmacFileContents, err := userlib.HMACEval(hmacKey, contentData)
	if err != nil {
		return errors.New("error calculating HMAC for file content")
	}
	file.HMAC = hmacFileContents
	file.HMACKey = hmacKey

	//2. set encryption key to be this new file key
	marshalled_file, err := json.Marshal(file)
	if err != nil {
		return errors.New("error when marshalling content")
	}
	shared.FileKey = userlib.RandomBytes(16)
	marshalled_shared, err := json.Marshal(shared)
	if err != nil {
		return errors.New("error when marshalling content")
	}

	//HashKDF = key changes for new purpose
	IV_3 := userlib.RandomBytes(16)
	encryptedkey_filestruct, err := userlib.HashKDF(shared.FileKey, []byte("file struct encryption"))
	if err != nil {
		return errors.New("Error occurred while creating encryption key for file  struct")
	}
	encryptedFileStruct := userlib.SymEnc(encryptedkey_filestruct[:16], IV_3, marshalled_file)

	shared_bytes := []byte(userdata.Username + "shared")
	hash_shared_bytes := userlib.Hash(shared_bytes)
	shared_uuid, err := uuid.FromBytes(hash_shared_bytes[:16])
	if err != nil {
		return errors.New("1. error converting to UUID")
	}
	marshalled_node, err := json.Marshal(newContentPointer)
	userlib.DatastoreSet(newContentUUID, marshalled_node)
	//userlib.DatastoreSet()
	userlib.DatastoreSet(shared_uuid, marshalled_shared)
	userlib.DatastoreSet(fileUUID, encryptedFileStruct)
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	//TO DOOOO!!!!: not efficiently appending- try to fix
	//retrieve the file with storage key

	shared_bytes := []byte(userdata.Username + "shared")
	hashed_shared_bytes := userlib.Hash(shared_bytes)
	shared_uuid, err := uuid.FromBytes(hashed_shared_bytes[:16])
	if err != nil {
		return errors.New("1.error converting to UUID")
	}

	shared_struct, ok := userlib.DatastoreGet(shared_uuid)
	if !ok {
		return errors.New("1. error getting shared struct")
	}
	var ownerUsername string
	var ownerFilename string
	var shared Shared
	err = json.Unmarshal(shared_struct, &shared)
	if err != nil {
		return errors.New("error unmarshalling shared")
	}
	//if user == Owner
	if shared.Owner == userdata.Username {
		ownerFilename = filename
		ownerUsername = userdata.Username
		// user != Owner
	} else {
		inv_bytes := []byte(userdata.Username + "inv")
		hash_inv_bytes := userlib.Hash(inv_bytes)
		invitationUUID, err := uuid.FromBytes(hash_inv_bytes[:16])
		invitation_struct, ok := userlib.DatastoreGet(invitationUUID)
		if !ok {
			return errors.New("issue generating invitation uuid")
		}
		symm_bytes := []byte(userdata.Username + "SymmKey")
		hash_symm_bytes := userlib.Hash(symm_bytes)
		symmUUID, err := uuid.FromBytes(hash_symm_bytes[:16])
		symm_key, ok := userlib.DatastoreGet(symmUUID)
		if !ok {
			return errors.New("no symmkey")
		}
		decrypted_invitation := userlib.SymDec(symm_key, invitation_struct)
		var invitation Invitation
		err = json.Unmarshal(decrypted_invitation, &invitation)
		if err != nil {
			return errors.New("issue unmarshalling inv")
		}
		ownerFilename = invitation.FileOwnerName
		ownerUsername = invitation.OwnerUsername
	}

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(ownerFilename + ownerUsername))[:16])
	if err != nil {
		return errors.New("issue making storage key")
	}

	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return errors.New("1. file not found")
	}

	//decrypt file struct

	decryptedkey_filestruct_check := shared.FileKey

	//decryptedkey_filestruct_check := userlib.Argon2Key([]byte(userdata.Password), userlib.Hash([]byte(userdata.Username+userdata.Password)), 16)
	decryptedkey_filestruct, err := userlib.HashKDF(decryptedkey_filestruct_check, []byte("file struct encryption"))
	if err != nil {
		return errors.New("Error occurred while creating decryption key for file struct")
	}
	decryptedFileData := userlib.SymDec(decryptedkey_filestruct[:16], dataJSON)
	if decryptedFileData == nil {
		return errors.New("issue when decrypting")
	}
	var file File
	err = json.Unmarshal(decryptedFileData, &file)
	if err != nil {
		return errors.New("1. issue unmarshalling file struct")
	}

	currentNode := file.Head
	for currentNode != nil && currentNode.NextNode != nil {
		currentNode = currentNode.NextNode
	}

	newContentUUID := uuid.New()
	newContentPointer := &ContentPointer{
		UUID: newContentUUID,
	}
	newNode := &FileNode{
		UUID:     uuid.New(),
		Content:  newContentPointer,
		NextNode: nil,
	}

	IV := userlib.RandomBytes(16)
	newNode.Content.UUID = newContentUUID
	// Store the actual content in a separate map
	contentMap[newContentUUID] = userlib.SymEnc(file.FileKey, IV, content)

	// Add node to the linked list
	if currentNode == nil {
		file.Head = newNode
		file.Tail = newNode
	} else {
		currentNode.NextNode = newNode
		file.Tail = newNode
	}
	file.NodeCount++

	currentNode = file.Head
	contentData := contentMap[currentNode.Content.UUID]
	hmacFileContents, err := userlib.HMACEval(file.HMACKey, contentData)
	if err != nil {
		return errors.New("error calculating HMAC for file content")
	}
	file.HMAC = hmacFileContents

	//encrypt the file

	marshalled_file, err := json.Marshal(file)
	if err != nil {
		return errors.New("error when marshalling content")
	}

	IV_3 := userlib.RandomBytes(16)
	encryptedkey_filestruct, err := userlib.HashKDF(shared.FileKey, []byte("file struct encryption"))
	if err != nil {
		return errors.New("Error occurred while creating encryption key for file  struct")
	}
	encryptedFileStruct := userlib.SymEnc(encryptedkey_filestruct[:16], IV_3, marshalled_file)
	//TO DO: append to all users with access to file !!!!
	marshalled_node, err := json.Marshal(newContentPointer)
	if err != nil {
		return errors.New("unable ot marshall node")
	}
	userlib.DatastoreSet(newContentUUID, marshalled_node)
	userlib.DatastoreSet(storageKey, encryptedFileStruct)
	return nil

}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//obtain file data
	shared_bytes := []byte(userdata.Username + "shared")
	hashed_shared_bytes := userlib.Hash(shared_bytes)
	shared_uuid, err := uuid.FromBytes(hashed_shared_bytes[:16])
	if err != nil {
		return nil, errors.New("1.error converting to UUID")
	}
	shared_struct, ok := userlib.DatastoreGet(shared_uuid)
	if !ok {
		return nil, errors.New("1. error getting shared struct")
	}
	var ownerUsername string
	var ownerFilename string
	var shared Shared
	err = json.Unmarshal(shared_struct, &shared)
	if err != nil {
		return nil, errors.New("error unmarshalling shared")
	}
	//if user == Owner
	if shared.Owner == userdata.Username {
		ownerFilename = filename
		ownerUsername = userdata.Username
		// user != Owner
	} else {
		inv_bytes := []byte(userdata.Username + "inv")
		hash_inv_bytes := userlib.Hash(inv_bytes)
		invitationUUID, err := uuid.FromBytes(hash_inv_bytes[:16])
		invitation_struct, ok := userlib.DatastoreGet(invitationUUID)
		if !ok {
			return nil, errors.New("issue generating invitation uuid")
		}
		if len(invitation_struct) == 0 {
			return nil, errors.New("Invitation was revoked.")
		}
		symm_bytes := []byte(userdata.Username + "SymmKey")
		hash_symm_bytes := userlib.Hash(symm_bytes)
		symmUUID, err := uuid.FromBytes(hash_symm_bytes[:16])
		symm_key, ok := userlib.DatastoreGet(symmUUID)
		if !ok {
			return nil, errors.New("no symmkey")
		}
		decrypted_invitation := userlib.SymDec(symm_key, invitation_struct)
		var invitation Invitation
		err = json.Unmarshal(decrypted_invitation, &invitation)
		if err != nil {
			return nil, errors.New("issue unmarshalling inv")
		}
		ownerFilename = invitation.FileOwnerName
		ownerUsername = invitation.OwnerUsername
	}

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(ownerFilename + ownerUsername))[:16])
	if err != nil {
		return nil, errors.New("issue making storage key")
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("2. file not found!!!!"))
	}
	shared_bytes = []byte(userdata.Username + "shared")
	hashed_shared_bytes = userlib.Hash(shared_bytes)
	shared_uuid, err = uuid.FromBytes(hashed_shared_bytes[:16])
	if err != nil {
		return nil, errors.New("3. error converting to UUID")
	}
	shared_struct, ok = userlib.DatastoreGet(shared_uuid)
	if !ok {
		return nil, errors.New("3. error getting shared struct")
	}
	err = json.Unmarshal(shared_struct, &shared)
	if err != nil {
		return nil, errors.New("issue unmarshalling shared struct")
	}
	decryptedkey_filestruct_check := shared.FileKey

	//decryptedkey_filestruct_check := userlib.Argon2Key([]byte(userdata.Password), userlib.Hash([]byte(userdata.Username+userdata.Password)), 16)
	decryptedkey_filestruct, err := userlib.HashKDF(decryptedkey_filestruct_check, []byte("file struct encryption"))
	if err != nil {
		return nil, errors.New("Error occurred while creating decryption key for user struct")
	}
	decryptedFileData := userlib.SymDec(decryptedkey_filestruct[:16], dataJSON)
	if decryptedFileData == nil {
		return nil, errors.New("issue when decrypting")
	}

	var file File
	err = json.Unmarshal(decryptedFileData, &file)
	if err != nil {
		return nil, errors.New("!!!!issue unmarshalling file struct")
	}

	//HMAC file contents and check if HMACS are same!

	currentNode := file.Head
	contentData := contentMap[currentNode.Content.UUID]
	hmacFileContents, err := userlib.HMACEval(file.HMACKey, contentData)
	if err != nil {
		return nil, errors.New("error calculating HMAC for file content")
	}

	if !userlib.HMACEqual(file.HMAC, hmacFileContents) {
		return nil, errors.New("file contents have been tampered with")
	}
	for currentNode != nil {
		contentPointer := currentNode.Content
		if contentPointer == nil {
			return nil, errors.New("content pointer is nil")
		}

		// Retrieve the actual content using the content pointer
		contentUUID := contentPointer.UUID
		//contentDat, ok := userlib.DatastoreGet(contentUUID)
		if !ok {
			return nil, errors.New("unable to retrieve actual content")
		}
		contentData := contentMap[contentUUID]
		// Decrypt the content
		decryptedData := userlib.SymDec(file.FileKey, contentData)
		if decryptedData == nil {
			return nil, errors.New("problem decrypting file contents")
		}
		// Append the decrypted data to the content
		content = append(content, decryptedData...)

		// Move to the next node
		currentNode = currentNode.NextNode
	}
	//return decrypted file contents
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	// TODO: Check if the current user has access to the file or if they are a revoked user:
	invitationPtr uuid.UUID, err error) {
	//check if recipient is a person
	_, ok := userlib.KeystoreGet(recipientUsername + "public")
	if !ok {
		return uuid.Nil, errors.New("no such user exists")
	}

	shared_bytes := []byte(userdata.Username + "shared")
	hashed_shared_bytes := userlib.Hash(shared_bytes)
	shared_uuid, err := uuid.FromBytes(hashed_shared_bytes[:16])
	if err != nil {
		return uuid.Nil, errors.New("1.error converting to UUID")
	}
	shared_struct, ok := userlib.DatastoreGet(shared_uuid)
	if !ok {
		return uuid.Nil, errors.New("4. error getting shared struct")
	}
	// user != Owner
	var ownerUsername string
	var ownerFilename string
	var shared Shared
	err = json.Unmarshal(shared_struct, &shared)
	if err != nil {
		return uuid.Nil, errors.New("error unmarshalling shared")
	}
	if shared.Owner == userdata.Username {
		ownerFilename = filename
		ownerUsername = userdata.Username
	} else {
		inv_bytes := []byte(userdata.Username + "inv")
		hash_inv_bytes := userlib.Hash(inv_bytes)
		invitationUUID, err := uuid.FromBytes(hash_inv_bytes[:16])
		invitation_struct, ok := userlib.DatastoreGet(invitationUUID)
		if !ok {
			return uuid.Nil, errors.New("issue generating invitation uuid")
		}
		symm_bytes := []byte(userdata.Username + "SymmKey")
		hash_symm_bytes := userlib.Hash(symm_bytes)
		symmUUID, err := uuid.FromBytes(hash_symm_bytes[:16])
		symm_key, ok := userlib.DatastoreGet(symmUUID)
		if !ok {
			return uuid.Nil, errors.New("no symmkey")
		}
		decrypted_invitation := userlib.SymDec(symm_key, invitation_struct)
		var invitation Invitation
		err = json.Unmarshal(decrypted_invitation, &invitation)
		if err != nil {
			return uuid.Nil, errors.New("issue unmarshalling inv")
		}
		ownerFilename = invitation.FileOwnerName
		ownerUsername = invitation.OwnerUsername
	}

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(ownerFilename + ownerUsername))[:16])
	if err != nil {
		return uuid.Nil, errors.New("issue making storage key")
	}

	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return uuid.Nil, errors.New("3. file not found")
	}

	//decrypt file struct
	decryptedkey_filestruct_check := shared.FileKey
	//decryptedkey_filestruct_check := userlib.Argon2Key([]byte(userdata.Password), userlib.Hash([]byte(userdata.Username+userdata.Password)), 16)
	decryptedkey_filestruct, err := userlib.HashKDF(decryptedkey_filestruct_check, []byte("file struct encryption"))
	if err != nil {
		return uuid.Nil, errors.New("Error occurred while creating decryption key for file struct")
	}
	decryptedFileData := userlib.SymDec(decryptedkey_filestruct[:16], dataJSON)
	if decryptedFileData == nil {
		return uuid.Nil, errors.New("issue when decrypting")
	}
	var file File
	err = json.Unmarshal(decryptedFileData, &file)
	if err != nil {
		return uuid.Nil, errors.New("3. issue unmarshalling file struct")
	}
	//generate signature using private key of user
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return uuid.Nil, errors.New("error generating signature keys")
	}
	userlib.KeystoreSet(userdata.Username+"verify", DSVerifyKey)

	//Generate a unique invitation UUID
	inv_bytes := []byte(recipientUsername + "inv")
	hash_inv_bytes := userlib.Hash(inv_bytes)
	invitationUUID, err := uuid.FromBytes(hash_inv_bytes[:16])
	// Create and store the invitation object
	var myEmptySlice = make([]byte, 0)
	new_invitation := Invitation{
		UUID:           invitationUUID,
		FileName:       filename,
		SenderUsername: userdata.Username,
		OwnerUsername:  file.Owner,
		FileOwnerName:  "",
		FileKey:        myEmptySlice, //TODOOOOOOOOO
		Accepted:       false,
	}
	if shared.Owner == userdata.Username {
		new_invitation.FileOwnerName = filename
	} else {
		inv_bytes := []byte(userdata.Username + "inv")
		hash_inv_bytes := userlib.Hash(inv_bytes)
		invitationUUID, err := uuid.FromBytes(hash_inv_bytes[:16])
		invitation_struct, ok := userlib.DatastoreGet(invitationUUID)
		if !ok {
			return uuid.Nil, errors.New("issue generating invitation uuid")
		}
		symm_bytes := []byte(userdata.Username + "SymmKey")
		hash_symm_bytes := userlib.Hash(symm_bytes)
		symmUUID, err := uuid.FromBytes(hash_symm_bytes[:16])
		symm_key, ok := userlib.DatastoreGet(symmUUID)
		if !ok {
			return uuid.Nil, errors.New("no symmkey")
		}
		decrypted_invitation := userlib.SymDec(symm_key, invitation_struct)
		var invitation Invitation
		err = json.Unmarshal(decrypted_invitation, &invitation)
		if err != nil {
			return uuid.Nil, errors.New("issue unmarshalling inv")
		}
		new_invitation.FileOwnerName = invitation.FileOwnerName
	}
	//IDEA: hashkdf for encrypting and decrypting invitation with user's public key--> if they have access should work, if revoked public key will not work
	//TO DO: how to store access list--> encrypt list with owner's public key (Argon2Key)

	marshalled_struct, err := json.Marshal(new_invitation)
	if err != nil {
		return uuid.Nil, errors.New("2: issue marshalling struct")
	}
	hmacKey := userlib.RandomBytes(16)

	hmacFileContents, err := userlib.HMACEval(hmacKey, marshalled_struct)
	if err != nil {
		return uuid.Nil, errors.New("error when creating HMAC/evaluating HMAC")
	}
	err = json.Unmarshal(marshalled_struct, &new_invitation)
	if err != nil {
		return uuid.Nil, errors.New("issue unmarshalling struct")
	}

	hmac_bytes := []byte(userdata.Username + "hmac")
	hash_hmac_bytes := userlib.Hash(hmac_bytes)
	hmacUUID, err := uuid.FromBytes(hash_hmac_bytes[:16])

	hmacKey_bytes := []byte(userdata.Username + "hmacKey")
	hash_hmacKey_bytes := userlib.Hash(hmacKey_bytes)
	hmacKeyUUID, err := uuid.FromBytes(hash_hmacKey_bytes[:16])

	userlib.DatastoreSet(hmacUUID, hmacFileContents)
	userlib.DatastoreSet(hmacKeyUUID, hmacKey)
	//SIGN STRUCT
	marshalled_struct, err = json.Marshal(new_invitation)
	if err != nil {
		return uuid.Nil, errors.New("2: issue marshalling struct")
	}
	signature, err := userlib.DSSign(DSSignKey, marshalled_struct)
	if err != nil {
		return uuid.Nil, errors.New("issue making signature")
	}
	err = json.Unmarshal(marshalled_struct, &new_invitation)
	if err != nil {
		return uuid.Nil, errors.New("issue unmarshalling struct")
	}
	sig_bytes := []byte(userdata.Username + "SigKey")
	hash_sig_bytes := userlib.Hash(sig_bytes)
	sigUUID, err := uuid.FromBytes(hash_sig_bytes[:16])
	userlib.DatastoreSet(sigUUID, signature)

	marshalled_struct, err = json.Marshal(new_invitation)
	if err != nil {
		return uuid.Nil, errors.New("error when marshalling struct")
	}

	IV := userlib.RandomBytes(16)
	symm_key := userlib.RandomBytes(16)
	encrypted_marshall := userlib.SymEnc(symm_key, IV, marshalled_struct)
	//HMAC THE INV
	hmacKey_enc := userlib.RandomBytes(16)
	hmacFileContents_enc, err := userlib.HMACEval(hmacKey_enc, encrypted_marshall)
	if err != nil {
		return uuid.Nil, errors.New("error when creating HMAC/evaluating HMAC")
	}
	//get receipient public key
	rec_pub, ok := userlib.KeystoreGet(recipientUsername + "public")
	if !ok {
		return uuid.Nil, errors.New("issue getting recipient's public key")
	}

	//ENCRYPT THE HMAC W RECIPIENTS PUBLIC KEY
	encrypted_hmacFileContents, err := userlib.PKEEnc(rec_pub, hmacFileContents_enc)
	if err != nil {
		return uuid.Nil, errors.New("issue encrypting hmac")
	}
	encrypted_hmacKey, err := userlib.PKEEnc(rec_pub, hmacKey_enc)
	if err != nil {
		return uuid.Nil, errors.New("issue encrypting hmac key")
	}

	//STORE THE KEY IN SENDERS SHARED TO
	shared.EncInvHMAC = encrypted_hmacFileContents
	shared.EncInvHMACKey = encrypted_hmacKey

	symm_bytes := []byte(recipientUsername + "SymmKey")
	hash_symm_bytes := userlib.Hash(symm_bytes)
	symmUUID, err := uuid.FromBytes(hash_symm_bytes[:16])
	if err != nil {
		return uuid.Nil, errors.New("1. error converting to UUID")
	}

	marshalled_shared, err := json.Marshal(shared)
	if err != nil {
		return uuid.Nil, errors.New("error when marshalling shared in append")
	}

	userlib.DatastoreSet(shared_uuid, marshalled_shared)

	userlib.DatastoreSet(symmUUID, symm_key)

	userlib.DatastoreSet(invitationUUID, encrypted_marshall) // encrypted invitation
	//Return the generated invitation UUID
	return invitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// go into inivatation struct
	// look for univeral file name
	// check if {universal file name: flagged = true}
	//if flagged == true --> error

	//decrypt invitation with private key

	invitation_struct, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("issue getting invitation")
	}

	if len(invitation_struct) == 0 {
		return errors.New("Invitation was revoked.")
	}

	symm_bytes := []byte(userdata.Username + "SymmKey")
	hash_symm_bytes := userlib.Hash(symm_bytes)
	symmUUID, err := uuid.FromBytes(hash_symm_bytes[:16])
	symm_key, ok := userlib.DatastoreGet(symmUUID)
	if !ok {
		return errors.New("no symmkey")
	}

	//go into sender's shared and get HMAC and HMAC key
	var hmac_shared Shared
	shared_bytes := []byte(senderUsername + "shared")
	hashed_shared_bytes := userlib.Hash(shared_bytes)
	shared_uuid, err := uuid.FromBytes(hashed_shared_bytes[:16])
	if err != nil {
		return errors.New("3. error converting to UUID")
	}
	hmac_shared_struct, ok := userlib.DatastoreGet(shared_uuid)
	if !ok {
		return errors.New("3. error getting shared struct")
	}
	err = json.Unmarshal(hmac_shared_struct, &hmac_shared)
	if err != nil {
		return errors.New("issue unmarshalling shared struct")
	}
	enc_hmac := hmac_shared.EncInvHMAC
	enc_hmac_key := hmac_shared.EncInvHMACKey
	//decrypt HMAC and HMAC key with user's private key
	rec_priv := userdata.PrivKey
	dec_hmac, err := userlib.PKEDec(rec_priv, enc_hmac)
	if err != nil {
		return errors.New("issue decrypting hmac")
	}
	dec_hmac_key, err := userlib.PKEDec(rec_priv, enc_hmac_key)
	if err != nil {
		return errors.New("issue decrypting hmac key")
	}
	//HMAC invitation
	hmacFileContents_enc, err := userlib.HMACEval(dec_hmac_key, invitation_struct)
	if err != nil {
		return errors.New("error when creating HMAC/evaluating HMAC")
	}
	//check if HMAC's are same
	check_hmac := userlib.HMACEqual(hmacFileContents_enc, dec_hmac)
	if !check_hmac {
		return errors.New("Invitation has been tampered with!")
	}

	decrypted_invitation := userlib.SymDec(symm_key, invitation_struct)
	if !ok {
		return errors.New("No username in keyStore for verification key")
	}
	if err != nil {
		return errors.New("issue marshalling invitation")
	}
	// unmarshall invit struct
	var invitation Invitation
	err = json.Unmarshal(decrypted_invitation, &invitation)
	if err != nil {
		return errors.New("issue unmarshalling invitation struct")
	}
	//check if accepted bool is false--> if true, ERROR
	hmac_bytes := []byte(senderUsername + "hmac")
	hash_hmac_bytes := userlib.Hash(hmac_bytes)
	hmacUUID, err := uuid.FromBytes(hash_hmac_bytes[:16])

	hmacKey_bytes := []byte(senderUsername + "hmacKey")
	hash_hmacKey_bytes := userlib.Hash(hmacKey_bytes)
	hmacKeyUUID, err := uuid.FromBytes(hash_hmacKey_bytes[:16])
	hmac_key, ok := userlib.DatastoreGet(hmacKeyUUID)
	if !ok {
		return errors.New("issue getting hmac key")
	}
	invitation_hmac, ok := userlib.DatastoreGet(hmacUUID)
	if !ok {
		return errors.New("issue getting hmac")
	}

	marshalled_struct, err := json.Marshal(invitation)
	if err != nil {
		return errors.New("unable to marshal inv !")
	}
	//HMAC invitation to make sure it hasn't been tampered with?
	HMACInvt, err := userlib.HMACEval(hmac_key, marshalled_struct)
	if err != nil {
		return errors.New("unable to hmac invitation")
	}

	if !userlib.HMACEqual(invitation_hmac, HMACInvt) {
		return errors.New("hmac not the same")
	}
	err = json.Unmarshal(marshalled_struct, &invitation)
	if err != nil {
		return errors.New("issue unmarshalling invitation struct")
	}
	//check if accepted bool is false--> if true, ERROR
	if invitation.Accepted == true {
		return errors.New("Already accepted invitation.")
	}
	if invitation.SenderUsername != senderUsername {
		return errors.New("Invitation not sent by sender.")
	}
	//set accepted bool to true
	invitation.Accepted = true
	//add to access struct
	fileUUID, err := uuid.FromBytes(userlib.Hash([]byte(invitation.FileOwnerName + invitation.OwnerUsername))[:16])
	if err != nil {
		return errors.New("issue when creating storage key")
	}
	var myEmptySlice = make([]byte, 0)
	//var recshared Shared
	emptyShared := make(map[string]*Shared)
	emptyRedFlag := make(map[string][]string)
	emptyInv := make(map[string]*Invitation)
	rec_shared := Shared{
		UniveralUUID:   fileUUID,
		Username:       userdata.Username,
		FileName:       "",
		Owner:          invitation.OwnerUsername,
		FileKey:        myEmptySlice,
		SharedTo:       emptyShared,
		RedFlag:        emptyRedFlag,
		InvitationPtrs: emptyInv,
	}

	//create new name for file --> check if file name doesn't already exist in their namespace
	name := filename
	_, exists := userdata.FileNames[filename] //TODO: check if this works: printing blank uuid right now
	// Check if the key exists
	if exists {
		return errors.New("file name already exists")
	} else {
		rec_shared.FileName = name
	}
	userdata.FileNames[filename] = fileUUID
	//generate new key in (filename.Owner gen new keys HashKDF) --> send
	//owner shared stuct:
	var owner_shared_var Shared
	owner_shared_bytes := []byte(invitation.OwnerUsername + "shared")
	owner_hash_shared_bytes := userlib.Hash(owner_shared_bytes)
	owner_shared_uuid, err := uuid.FromBytes(owner_hash_shared_bytes[:16])
	if err != nil {
		return errors.New("1. error converting to UUID")
	}
	owner_shared, ok := userlib.DatastoreGet(owner_shared_uuid)
	if !ok {
		return errors.New("issue getting shared struct")
	}
	err = json.Unmarshal(owner_shared, &owner_shared_var)
	if err != nil {
		return errors.New("issue unmarshalling shared")
	}
	value, _ := owner_shared_var.RedFlag[invitation.FileOwnerName]
	for _, name := range value {
		if name == userdata.Username {
			return errors.New("You have been revoked.")
		}
	}

	//update person who's sharing's shared struct's sharedto
	var sender_shared_var Shared
	sender_shared_bytes := []byte(senderUsername + "shared")
	sender_hash_shared_bytes := userlib.Hash(sender_shared_bytes)
	sender_shared_uuid, err := uuid.FromBytes(sender_hash_shared_bytes[:16])
	if err != nil {
		return errors.New("1. error converting to UUID")
	}
	sender_shared, ok := userlib.DatastoreGet(sender_shared_uuid)
	if !ok {
		return errors.New("issue getting shared struct")
	}
	err = json.Unmarshal(sender_shared, &sender_shared_var)
	if err != nil {
		return errors.New("issue unmarshalling shared")
	}
	/////
	rec_shared.FileKey = sender_shared_var.FileKey
	//shared.SharedTo[userdata.Username] = append((shared.SharedTo)[userdata.Username] , &rec_shared)
	(sender_shared_var.SharedTo)[userdata.Username] = &rec_shared
	(sender_shared_var.InvitationPtrs)[userdata.Username] = &invitation
	marshalled_sender_shared, err := json.Marshal(sender_shared_var)
	if err != nil {
		return errors.New("issue marshalling shared")
	}
	userlib.DatastoreSet(sender_shared_uuid, marshalled_sender_shared)
	//set shared struct
	marshalled_shared, err := json.Marshal(rec_shared)
	if err != nil {
		return errors.New("issue marshalling shared")
	}
	shared_bytes = []byte(userdata.Username + "shared")
	hash_shared_bytes := userlib.Hash(shared_bytes)
	shared_uuid, err = uuid.FromBytes(hash_shared_bytes[:16])
	if err != nil {
		return errors.New("1. error converting to UUID")
	}
	userlib.DatastoreSet(shared_uuid, marshalled_shared)
	//encrypt struct
	IV := userlib.RandomBytes(16)
	encrypted_marshall := userlib.SymEnc(symm_key, IV, marshalled_struct)

	userlib.DatastoreSet(invitationPtr, encrypted_marshall)
	shared_get, ok := userlib.DatastoreGet(sender_shared_uuid)
	if !ok {
		return errors.New("")
	}
	var checkShared Shared
	err = json.Unmarshal(shared_get, &checkShared)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//TO DOOOOOO!!!: edge case where revoke before invite is accepted
	// go into shared struct
	// add mapping to flagged dictionaty {universal file name: flagged = true }

	//run a check that user is the owner of filename
	//check if userdata.username + filename gives you access to the file because owner username and owner file name is storagekey
	//or just go into the file and decrypt and check that userdata.username == file's owner (file.Owner)
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return errors.New("error getting storage ")
	}

	//Get the shared struct
	shared_bytes := []byte(userdata.Username + "shared")
	hashed_shared_bytes := userlib.Hash(shared_bytes)
	shared_uuid, err := uuid.FromBytes(hashed_shared_bytes[:16])
	if err != nil {
		return errors.New("error converting to UUID")
	}
	shared_struct, ok := userlib.DatastoreGet(shared_uuid)
	if !ok {

		return errors.New("issue creating datastore.")
	}
	var owner_shared Shared
	err = json.Unmarshal(shared_struct, &owner_shared)
	if err != nil {
		return errors.New("issue unmarshalling shared struct")
	}
	//check if user is owner of file
	//Regive access
	//generate new key

	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return errors.New(strings.ToTitle("4. file not found"))
	}
	decryptedkey_filestruct_check := owner_shared.FileKey
	decryptedkey_filestruct, err := userlib.HashKDF(decryptedkey_filestruct_check, []byte("file struct encryption"))
	if err != nil {
		return errors.New("Error occurred while creating decryption key for user struct")
	}
	decryptedFileData := userlib.SymDec(decryptedkey_filestruct[:16], dataJSON)
	if decryptedFileData == nil {
		return errors.New("issue when decrypting")
	}
	var file File
	err = json.Unmarshal(decryptedFileData, &file)
	if err != nil {
		return errors.New("2. issue unmarshalling file struct")
	}

	var newFileKey []byte = userlib.RandomBytes(16)
	owner_shared.FileKey = newFileKey
	marshalled_file, err := json.Marshal(file)
	if err != nil {
		return errors.New("error when marshalling shared in append")
	}
	IV_3 := userlib.RandomBytes(16)
	encryptedkey_filestruct, err := userlib.HashKDF(newFileKey, []byte("file struct encryption"))
	if err != nil {
		return errors.New("Error occurred while creating encryption key for file  struct")
	}
	encryptedFileStruct := userlib.SymEnc(encryptedkey_filestruct[:16], IV_3, marshalled_file)
	userlib.DatastoreSet(storageKey, encryptedFileStruct)

	// go into shared struct to redistribute keys to pntrs that are not the recipient username
	//if recipientUsername not in shared.SharedTo
	_, found := owner_shared.SharedTo[recipientUsername]
	// Check if the key is not present
	//map[bob]
	myInv := owner_shared.InvitationPtrs[recipientUsername]
	if !found {
		owner_shared.RedFlag[filename] = append(owner_shared.RedFlag[filename], recipientUsername)
	} else {
		//userdata.updateRevoke(recipientUsername, newFileKey, myInv, shared)
		for name, _ := range owner_shared.SharedTo {
			if name != recipientUsername {
				//err = json.Unmarshal(user_shareTo_struct, &userShare)
				//user_shareTo_struct.FileKey = newFileKey
				var name_shared Shared
				name_bytes := []byte(name + "shared")
				name_hashed_shared_bytes := userlib.Hash(name_bytes)
				name_shared_uuid, err := uuid.FromBytes(name_hashed_shared_bytes[:16])
				name_marsh, ok := userlib.DatastoreGet(name_shared_uuid)
				if !ok {
					return errors.New("issue getting id")
				}
				err = json.Unmarshal(name_marsh, &name_shared)
				name_shared.FileKey = newFileKey
				//marshalled_shared, err := json.Marshal(user_shareTo_struct)
				// if err != nil {
				// 	return errors.New("issue marshalling shared in for loop")
				// }
				// //userlib.DatastoreSet(shared_uuid, marshalled_shared)
				// if err != nil {
				// 	return errors.New("error converting to UUID")
				// }
				// recipient_shared, ok := userlib.DatastoreGet(name_shared_uuid)
				// if !ok {
				// 	return errors.New("issue getting recipient's shared struct")
				// }
				// var recipientShared Shared
				// err = json.Unmarshal(recipient_shared, &recipientShared)
				// if err != nil {
				// 	return errors.New("issue unmarshalling recipient's shared")
				// }
				marshalled_recipient_shared, err := json.Marshal(name_shared)
				if err != nil {
					return errors.New("issue marshalling recipient's shared")
				}
				userlib.DatastoreSet(name_shared_uuid, marshalled_recipient_shared)
				updateFileKeyRecursively(&name_shared, newFileKey)
			} else {
				//TODO: recursively delete stuff for children as well
				userlib.DatastoreDelete(myInv.UUID)
				delete(owner_shared.SharedTo, recipientUsername)
			}
		}
	}

	// marshall shared struct
	marshalled_shared, err := json.Marshal(owner_shared)
	if err != nil {
		return errors.New("error when marshalling shared in append")
	}

	//put shared stuct back in datastore
	userlib.DatastoreSet(shared_uuid, marshalled_shared)
	//change UUID of file (go back into head / tail)
	return nil
}

func (userdata *User) hybridEncrypt(publicKey userlib.PublicKeyType, data []byte) (content []byte, symmKey []byte, err error) {
	symmetricKey := userlib.RandomBytes(16)
	encrypted_sym_key, err := userlib.PKEEnc(publicKey, symmetricKey)
	if err != nil {
		return nil, nil, errors.New("unable to encrpt")
	}
	IV := userlib.RandomBytes(16)
	encrypted_data := userlib.SymEnc(encrypted_sym_key[:16], IV, data)

	if encrypted_data == nil {
		return nil, nil, errors.New("issue with enrcrypting data")
	}
	return encrypted_data, encrypted_sym_key, nil
}

func (userdata *User) hybridDecrypt(data []byte, enc_symmKey []byte, private_key userlib.PrivateKeyType) (decrypt_content []byte, err error) {
	decrypted_sym_key, err := userlib.PKEDec(private_key, enc_symmKey)

	if err != nil {
		return nil, errors.New("issue when decrypting symmetric key")
	}
	decrypted_data := userlib.SymDec(decrypted_sym_key[:16], data)
	if decrypted_data == nil {
		return nil, errors.New("issue when decrypting data")
	}
	return decrypted_data, nil
}

func (userdata *User) genNewKey(ownerUsername string, filename string, purpose string) (returned_key []byte, err error) {
	// decrypt file
	// gen new kwy
	// encrypt file

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}

	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("4. file not found"))
	}

	shared_bytes := []byte(userdata.Username + "shared")
	hashed_shared_bytes := userlib.Hash(shared_bytes)
	shared_uuid, err := uuid.FromBytes(hashed_shared_bytes[:16])
	if err != nil {
		return nil, errors.New("error converting to UUID")
	}
	shared_struct, ok := userlib.DatastoreGet(shared_uuid)
	if !ok {
		return nil, errors.New("7. error getting shared struct")
	}
	var shared Shared
	err = json.Unmarshal(shared_struct, &shared)
	if err != nil {
		return nil, errors.New("issue unmarshalling shared struct")
	}
	decryptedkey_filestruct := shared.FileKey
	decryptedFileData := userlib.SymDec(decryptedkey_filestruct[:16], dataJSON)
	if decryptedFileData == nil {
		return nil, errors.New("issue when decrypting")
	}
	var file File
	err = json.Unmarshal(decryptedFileData, &file)
	if err != nil {
		return nil, errors.New("??? issue unmarshalling file struct")
	}
	var newFileKey []byte = userlib.RandomBytes(16)

	IV_3 := userlib.RandomBytes(16)
	encryptedkey_filestruct, err := userlib.HashKDF(newFileKey, []byte(purpose))
	if err != nil {
		return nil, errors.New("Error occurred while creating encryption key for file  struct")
	}
	marshalled_file, err := json.Marshal(file)
	if err != nil {
		return nil, errors.New("error when marshalling content")
	}

	encryptedFileStruct := userlib.SymEnc(encryptedkey_filestruct[:16], IV_3, marshalled_file)
	userlib.DatastoreSet(storageKey, encryptedFileStruct)
	return newFileKey, nil

}

func (userdata *User) updateRevoke(recipientUsername string, newFileKey []byte, myInv *Invitation, shared Shared) (err error) {
	//var shared Shared
	for name, user_shareTo_struct := range shared.SharedTo {
		if name != recipientUsername {
			//err = json.Unmarshal(user_shareTo_struct, &userShare)
			user_shareTo_struct.FileKey = newFileKey
			marshalled_shared, err := json.Marshal(user_shareTo_struct)
			if err != nil {
				return errors.New("issue marshalling shared in for loop")
			}
			shared_bytes := []byte(name + "shared")
			hashed_shared_bytes := userlib.Hash(shared_bytes)
			shared_uuid, err := uuid.FromBytes(hashed_shared_bytes[:16])
			userlib.DatastoreSet(shared_uuid, marshalled_shared)

			//added
			if err != nil {
				return errors.New("error converting to UUID")
			}
			recipient_shared, ok := userlib.DatastoreGet(shared_uuid)
			if !ok {
				return errors.New("issue getting recipient's shared struct")
			}
			var recipientShared Shared
			err = json.Unmarshal(recipient_shared, &recipientShared)
			if err != nil {
				return errors.New("issue unmarshalling recipient's shared")
			}
			// Update the FileKey recursively for the recipient's SharedTo
			updateFileKeyRecursively(&recipientShared, newFileKey)

			marshalled_recipient_shared, err := json.Marshal(recipientShared)
			if err != nil {
				return errors.New("issue marshalling recipient's shared")
			}
			userlib.DatastoreSet(shared_uuid, marshalled_recipient_shared)
		} else {
			userlib.DatastoreDelete(myInv.UUID)
			delete(shared.SharedTo, recipientUsername)
		}

		//go into name's shared:
		//updated their sharedto
		//go into THEIR sharedto
		//break loop when sharedto is empty
	}
	return nil
}

func updateFileKeyRecursively(shared *Shared, newFileKey []byte) (err error) {

	for name, user_shareTo_struct := range shared.SharedTo {
		// Update the FileKey of the current user
		user_shareTo_struct.FileKey = newFileKey
		shared_bytes := []byte(name + "shared")
		hashed_shared_bytes := userlib.Hash(shared_bytes)
		shared_uuid, err := uuid.FromBytes(hashed_shared_bytes[:16])
		if err != nil {
			return errors.New("issue getting id")
		}
		marshalled_shared, err := json.Marshal(user_shareTo_struct)
		if err != nil {
			return errors.New("issue marshalling")
		}
		userlib.DatastoreSet(shared_uuid, marshalled_shared)
		// Recursively update the FileKey of descendants
		updateFileKeyRecursively(user_shareTo_struct, newFileKey)
	}
	return nil
}
