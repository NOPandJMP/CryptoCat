package main

import (
	"crypto/rsa"
	"fmt"
	gooper "github.com/Number571/gopeer"
	utils "github.com/RAXandEAX/CryptoCat"
	"net"
	"os"
)

var (
	Rooms                 = make(map[string]*Room)
	Users                 = make(map[net.Conn]*User)
	UsersConn             = make(map[net.Conn]string)
	UsersSessKey          = make(map[net.Conn][]byte)
	PrivateKey, PublicKey = &rsa.PrivateKey{}, gooper.StringToPublicKey(utils.PublickServerKey)
)

const ServerNickName = "Server"

//Structure of the room to store information and make it easier to work with it
type Room struct {
	owner       net.Conn
	roomSessKey []byte
	roomCode    string
	usersRoom   map[net.Conn]bool
}

//The user structure to store his public key, room list and list of encrypted session keys
type User struct {
	PubKey   *rsa.PublicKey
	ListRoom []string
	RoomKeys map[string]string
}

func main() {
	var err error
	PrivateKey, err = utils.LoadPrivateServerKey([]byte("123"))
	if err != nil {
		utils.PrintError(err)
		os.Exit(1)
	}

	//Initializing the server
	ln, err := net.Listen("tcp", "0.0.0.0:9090")
	if err != nil {
		utils.PrintError(err)
		os.Exit(2)
	}

	fmt.Println("Server started on 0.0.0.0:9090")

	//Defer is used to execute a function after the function in which it is
	defer ln.Close()

	//Infinite loop , in which we will take the connection
	for {
		conn, err := ln.Accept()
		if err != nil {
			utils.PrintError(err)
			continue
		}

		go handleConn(conn)
	}

}

func handleConn(conn net.Conn) {
	handShake(conn)
	for {
		msg := utils.ReadMessage(conn)
		if msg == nil {
			break
		}
		switch msg.Option {
		case utils.CREATE_ROOM:
			createRoom(conn, msg)
		case utils.JOIN_ROOM:
			joinRoom(conn, msg)

		}
	}

}

func handShake(conn net.Conn) {
	msg := utils.ReadMessage(conn)
	UsersConn[conn] = msg.NickName

	user := new(User)
	user.PubKey = gooper.BytesToPublicKey(msg.Data)
	Users[conn] = user
	sessKeys := utils.GenerateSessionKey(32)
	UsersSessKey[conn] = sessKeys

	msg = utils.NewMessage(utils.Empty, gooper.EncryptRSA(user.PubKey, sessKeys), "", ServerNickName)
	utils.SendMessage(conn, msg)

}

func createRoom(conn net.Conn, msg *utils.Message) {
	room := new(Room)
	room.owner = conn
	room.usersRoom = make(map[net.Conn]bool)
	room.roomSessKey = utils.GenerateSessionKey(32)
	room.roomCode = utils.RandStringBytes(10)
	Rooms[msg.RoomName] = room
	msg = utils.NewMessage(utils.CREATE_ROOM, utils.StringToBytes(fmt.Sprintf("Save the access code to the room, if you lose the key, you lose access to the room. Code : %s", room.roomCode)), msg.RoomName, ServerNickName)
	utils.SendMessageWhithEncrypt(conn, msg, UsersSessKey[conn])

}

func joinRoom(conn net.Conn, msg *utils.Message) {

	if room, ok := Rooms[msg.RoomName]; ok {
		if room.roomCode == string(gooper.DecryptAES(UsersSessKey[conn], msg.Data)) {
			room.usersRoom[conn] = true
			msg = utils.NewMessage(utils.Empty, room.roomSessKey, msg.RoomName, ServerNickName)
			utils.SendMessageWhithEncrypt(conn, msg, UsersSessKey[conn])
		} else {
			msg = utils.NewMessage(utils.ERROR, utils.StringToBytes("Wrong key"), msg.RoomName, ServerNickName)
			utils.SendMessageWhithEncrypt(conn, msg, UsersSessKey[conn])
		}

	} else {
		msg = utils.NewMessage(utils.ERROR, utils.StringToBytes("The room does not exist"), msg.RoomName, ServerNickName)
		utils.SendMessageWhithEncrypt(conn, msg, UsersSessKey[conn])
	}
}
