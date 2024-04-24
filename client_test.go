package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors" //TODO Delete this import
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "cookies123"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const contentFour = "It is a truth universally acknowledged, that a single man in possession of a good fortune, must be in want of a wife." +
	"However little known the feelings or views of such a man may be on his first entering a neighbourhood, this truth is so well fixed " +
	"in the minds of the surrounding families, that he is considered as the rightful property of some one or another of their daughters."

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {
		Specify("Basic Test: Testing incorrect password.", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", "cookies1234")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Password authentication successfully failed.")
		})

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Single User Store/Load/.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Test: Set/load existing file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data again: %s", contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("Basic Test: Append Bandwidth", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			before := userlib.DatastoreGetBandwidth()
			userlib.DebugMsg("alice appending to file %s, content: %s", aliceFile, contentFour)
			err = alice.AppendToFile(aliceFile, []byte(contentFour))
			Expect(err).To(BeNil())

			after := userlib.DatastoreGetBandwidth()
			bandwidth_1 := after - before

			before = after
			userlib.DebugMsg("alice appending to file %s, content: %s", aliceFile, contentFour)
			err = alice.AppendToFile(aliceFile, []byte(contentFour))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Testing bandwidth between first and second append.")
			after = userlib.DatastoreGetBandwidth()
			bandwidth_2 := after - before
			test_1 := bandwidth_2-bandwidth_1 < len(contentFour)+256
			Expect(test_1).To(Equal(true))

			before = after
			userlib.DebugMsg("alice appending to file %s, content: %s", aliceFile, contentFour)
			err = alice.AppendToFile(aliceFile, []byte(contentFour))
			Expect(err).To(BeNil())

			after = userlib.DatastoreGetBandwidth()
			bandwidth_3 := after - before
			test_2 := bandwidth_3-bandwidth_2 < len(contentFour)+256
			Expect(test_2).To(Equal(true))

			before = after
			userlib.DebugMsg("alice appending to file %s, content: %s", aliceFile, contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			after = userlib.DatastoreGetBandwidth()
			bandwidth_4 := after - before
			test_3 := bandwidth_4-bandwidth_3 < len(contentTwo)+256
			Expect(test_3).To(Equal(true))

			before = after
			userlib.DebugMsg("alice appending to file %s, content: a", aliceFile, 'a')
			err = alice.AppendToFile(aliceFile, []byte("a"))
			Expect(err).To(BeNil())

			after = userlib.DatastoreGetBandwidth()
			bandwidth_5 := after - before
			test_4 := bandwidth_5-bandwidth_4 < len("a")+256
			Expect(test_4).To(Equal(true))
		})
	})

	Describe("Revoked User Adversary", func() {
		Specify("Revoked Adversary attempts to access file.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", bobFile)
			err = alice.RevokeAccess(bobFile, "bob")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Oops...put in the wrong filename to revoke from.")

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Revoked adversary Bob accepts invitation again.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Revoked adversary Bob attempts to access shared file again.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Revoked adversary Bob attempts fetch invitation pointer from Datastore.")
			data, ok := userlib.DatastoreGet(invite)
			Expect(ok).To(Equal((false)))

			userlib.DebugMsg("Bob is doing some trolling...")
			var value []byte
			userlib.DatastoreSet(invite, value)

			userlib.DebugMsg("Bob is attempting to accept invitation again (rolls eyes).")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Revoked adversary Bob attempts to access shared file yet again (c'mon Bob).")
			data, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Datastore adversary", func() {
		Specify("Datastore adversary attempts to intercept Bob's invite and accept it on his behalf.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Eve.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve attempts to accept Bob's invite and gain access to aliceFile.")
			err = eve.AcceptInvitation("alice", invite, eveFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Datastore adversary appends to all of Alice's file pieces", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			dsmap := userlib.DatastoreGetMap()
			var alice_user uuid.UUID
			for name, _ := range dsmap {
				userlib.DebugMsg("Getting Alice's UUID value...")
				alice_user = name
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Datastore adversary tampers with Alice's file contents.")
			dsmap = userlib.DatastoreGetMap()
			for name, value := range dsmap {
				if name != alice_user {
					edited_contents := append(value, []byte("muhaha")...)
					userlib.DatastoreSet(name, edited_contents)
				}
			}

			userlib.DebugMsg("Alice tries to load from her tampered file.")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice tries to store new contents to her tampered file.")
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice tries to append to her tampered file.")
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Edge Cases", func() {
		Specify("Create invitation and revoke immediately.", func() {
			userlib.DebugMsg("Initializing users Alice, and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)

			userlib.DebugMsg("Checking that Alice can load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob cannot load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("InitUser with same username should error.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to initialize user Bob with empty username.")
			bob, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Attempting to initialize user Bob with same username as Alice.")
			bob, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Store and append empty content successfully.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with empty content", aliceFile)
			err = alice.StoreFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Load the Alice's file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("")))

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending null contents.")
			err = alice.AppendToFile(aliceFile, []byte(""))
			Expect(err).To(BeNil())
		})

		Specify("Tries to accept invitation with already existing filename.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepting invitation with different filename.")
			err = bob.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check Bob can load the file.")
			data, err := bob.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})
	})

	Describe("InitUser", func() {

		It("Init new user", func() {
			_, err := client.InitUser("Alice", "password")
			Expect(err).To(BeNil())
		})

		It("InitUser: Username case sensitive", func() {
			_, err1 := client.InitUser("ALICE", "password")
			_, err2 := client.InitUser("alice", "password")
			Expect(err1).To(BeNil(), "user does not exist")
			Expect(err2).To(BeNil(), "user does not exist")
		})

		It("InitUser: No error if password empty", func() {
			_, err := client.InitUser("Alice", "")
			Expect(err).To(BeNil())
		})

		It("InitUser: Error if username already exist", func() {
			_, err1 := client.InitUser("Alice", "password")
			_, err2 := client.InitUser("Alice", "password")
			Expect(err1).To(BeNil())
			Expect(err2).ToNot(BeNil())
		})

		It("InitUser: Error if username empty", func() {
			_, err := client.InitUser("", "password")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("GetUser", func() {
		It("Get User: correct password", func() {
			_, err1 := client.InitUser("Alice", "password")
			Expect(err1).To(BeNil())
			_, err2 := client.GetUser("Alice", "password")
			Expect(err2).To(BeNil())
		})

		It("GetUser: Error if wrong password", func() {
			_, err1 := client.InitUser("Alice", "password")
			Expect(err1).To(BeNil())
			_, err2 := client.GetUser("Alice", "wrongpassword")
			Expect(err2).ToNot(BeNil())
		})

		It("GetUser: Error if user not exist", func() {
			_, err := client.GetUser("Alice", "password")
			Expect(err).ToNot(BeNil())
		})

		It("GetUser: No Error if users have same password", func() {
			_, err := client.InitUser("Alice", "password")
			Expect(err).To(BeNil())
			_, err1 := client.GetUser("Alice", "password")
			Expect(err1).To(BeNil())
			_, err2 := client.InitUser("Bob", "password")
			Expect(err2).To(BeNil())
			_, err3 := client.GetUser("Bob", "password")
			Expect(err3).To(BeNil())
		})
	})

	Describe("StoreFile, LoadFile and AppendToFile", func() {
		It("filename can be empty", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("", []byte(contentOne))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			err = alice.AppendToFile("", []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = alice.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})

		It("error if load or append file not exist", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			_, err := alice.LoadFile("file2")
			Expect(err).ToNot(BeNil())

			err = alice.AppendToFile("file2", []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		It("2 user can use same filename", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("file1", []byte(contentOne))
			Expect(err).To(BeNil())

			err = bob.StoreFile("file1", []byte(contentOne))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile("file1")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = bob.LoadFile("file1")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		It("StoreFile, Append, and Load File", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
			userlib.DebugMsg("Final File:", string(data))
		})

		It("StoreFile same file twice", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
			userlib.DebugMsg("Final File:", string(data))
		})

		It("Error if load or append non-exist file", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		It("Append content is empty", func() {
			alice.StoreFile(aliceFile, []byte(contentOne))
			alice.AppendToFile(aliceFile, []byte{})

			content, _ := alice.LoadFile(aliceFile)
			Expect(content).To(BeEquivalentTo(contentOne))
		})

		It("Store content is empty", func() {
			alice.StoreFile(aliceFile, []byte{})
			alice.AppendToFile(aliceFile, []byte(contentOne))

			content, _ := alice.LoadFile(aliceFile)
			Expect(content).To(BeEquivalentTo(contentOne))
		})
	})

	Describe("CreateInvitation and AcceptInvitation", func() {
		It("Error if invalid username", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		It("Error if invalid filename", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		It("Valid Invitation", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invitation, "aliceFile")
			Expect(err).To(BeNil())

			data, err := bob.LoadFile("aliceFile")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			err = bob.AppendToFile("aliceFile", []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = bob.LoadFile("aliceFile")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			err = bob.StoreFile("aliceFile", []byte(contentThree))
			Expect(err).To(BeNil())

			data, err = bob.LoadFile("aliceFile")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
		})

		It("Error if load file before accept invitation", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err1 := bob.LoadFile("aliceFile")
			Expect(err1).ToNot(BeNil())
		})

		It("Error if store file and accept file using same file name", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())

			err = bob.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation("file", "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invitation, "file")
			Expect(err).ToNot(BeNil())
		})

		It("Tree invitation", func() {
			//alice -> bob&charles, bob->doris, charles->eve
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invitation, bobFile)
			Expect(err).To(BeNil())

			//alice -> charles
			invitation, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invitation, charlesFile)
			Expect(err).To(BeNil())

			//bob -> doris
			invitation, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("bob", invitation, dorisFile)
			Expect(err).To(BeNil())

			//charles -> eve
			invitation, err = charles.CreateInvitation(charlesFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("charles", invitation, eveFile)
			Expect(err).To(BeNil())
		})

		It("Fake invitation", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			bob, err = client.InitUser("bob", defaultPassword)
			charles, err = client.InitUser("charles", defaultPassword)
			alice.StoreFile(aliceFile, []byte(contentOne))
			charles.StoreFile(aliceFile, []byte(contentOne))
			fakeInvitation, _ := charles.CreateInvitation(aliceFile, "bob")
			err = bob.AcceptInvitation("alice", fakeInvitation, bobFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Revoke Access", func() {
		It("Testing Revoke Functionality with Multiple Shares", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charles, Doris and Eve.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charles accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Doris for file %s, and Doris accepting invite under name %s.", aliceFile, dorisFile)
			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris creating invite for Eve for file %s, and Eve accepting invite under name %s.", dorisFile, eveFile)
			invite, err = doris.CreateInvitation(dorisFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("doris", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob and Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Doris and Eve can still access the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the valid users can still append to the file.")
			err = doris.AppendToFile(dorisFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			err = eve.AppendToFile(eveFile, []byte(contentTwo))
			Expect(err).To(BeNil())
		})

		It("Can't create invitation after access revoked", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charles accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).ToNot(BeNil())
		})

		It("Append & Revoke & Append", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			//alice -> charles
			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			//bob can't append
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			//alice load content = 1+2+3
			content, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(string(content)).To(Equal(contentOne + contentTwo + contentThree))

			//charles append
			err = charles.AppendToFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())

			//charles load content = 1+2+3+3
			content, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(string(content)).To(Equal(contentOne + contentTwo + contentThree + contentThree))

			//alice load content
			content, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(string(content)).To(Equal(contentOne + contentTwo + contentThree + contentThree))
		})
	})

	Describe("Data Tampering Attack", func() {
		It("Tamper with all the content in the datastore", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			datastoreMap := userlib.DatastoreGetMap()

			for key, _ := range datastoreMap {
				userlib.DatastoreSet(key, []byte("garbage"))
			}

			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		It("Tamper with accepting invitation", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			bob, err = client.InitUser("bob", defaultPassword)

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			currentMap := make(map[uuid.UUID][]byte)
			for k, v := range userlib.DatastoreGetMap() {
				currentMap[k] = v
			}

			err = bob.AcceptInvitation("alice", invite, bobFile)

			userMap := userlib.DatastoreGetMap()
			for k := range userMap {
				if !bytesEqual(userMap[k], currentMap[k]) {
					userlib.DatastoreSet(k, []byte("garbage"))
				}
			}

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		It("Tamper with loading file", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			bob, err = client.InitUser("bob", defaultPassword)
			charles, err = client.InitUser("charles", defaultPassword)

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			currentMap := make(map[uuid.UUID][]byte)
			for k, v := range userlib.DatastoreGetMap() {
				currentMap[k] = v
			}

			_, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userMap := userlib.DatastoreGetMap()
			for k := range userMap {
				if !bytesEqual(userMap[k], currentMap[k]) {
					userlib.DatastoreSet(k, []byte("tamper content"))
					userlib.DebugMsg("Tamper success")
				}
			}

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			_, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
		})
	})
})

func getShortestKey(datastore map[userlib.UUID][]byte) userlib.UUID {
	var shortestKey userlib.UUID
	var shortestLength int
	shortestLength = 1<<31 - 1
	for key, value := range datastore {
		if len(value) < shortestLength && len(value) != 0 {
			shortestLength = len(value)
			shortestKey = key
		}
	}

	return shortestKey
}

// Helper function to get all keys in datastore map
func getAllKeys(datastore map[userlib.UUID][]byte) []userlib.UUID {
	var keys []userlib.UUID
	for k := range datastore {
		keys = append(keys, k)
	}
	return keys
}

// Helper function to get difference in two slices, return corresponding datastore key element pairs
func getDifference(slice1 []userlib.UUID, slice2 []userlib.UUID, datastore map[userlib.UUID][]byte) map[userlib.UUID][]byte {
	var diff []userlib.UUID
	for _, v := range slice1 {
		if !contains(slice2, v) {
			diff = append(diff, v)
		}
	}
	diffMap := make(map[userlib.UUID][]byte, len(diff))
	for _, v := range diff {
		diffMap[v] = datastore[v]
	}
	return diffMap
}

func contains(s []userlib.UUID, e userlib.UUID) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var equal bool = true
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			equal = false
		}
	}
	return equal
}
