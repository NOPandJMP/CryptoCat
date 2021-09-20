package main

import (
	"encoding/hex"
	"fmt"
	math "math/rand"
	"net"
	"strings"

	gooper "github.com/Number571/gopeer"
)

var (
	rooms                  = make(map[string]*Room) 
	users                  = make(map[string]*User)
	usersConn              = make(map[net.Conn]string)
	usersSessKey           = make(map[string][]byte)
	PrivateKey, PublickKey = GenerateKeyPair(2048)
)

const NickServer = "Server"

//Structure of the room to store information and make it easier to work with it 
type Room struct {
	owner     net.Conn
	usersRoom map[net.Conn]bool
}

//The user structure to store his public key, room list and list of encrypted session keys 
type User struct {
	connection net.Conn
	PubKey     []byte
	ListRoom   []string
	SessKeys   map[string]string
}

//List of characters , to create a random string 
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

//Function for creating a random string 
func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[math.Intn(len(letterBytes))]
	}
	return string(b)
}

func main() {
	//Initializing the server 
	ln, err := net.Listen("tcp", ":8080")
	LogFatal(err)

	//Defer is used to execute a function after the function in which it is
	defer ln.Close()

	//Infinite loop , in which we will take the connection 
	for {
		conn, err := ln.Accept()
		LogFatal(err)

		go handleConn(conn)
	}

}

//Function for handling connection and user requests 
func handleConn(conn net.Conn) {

	defer conn.Close()

	for {
		//We read the message and redirect it to a certain function based on the request parameter 
		msg := ReadMessage(conn)
		if msg == nil {
			break
		}
		switch msg.SwitchFlag {
		case REG:
			regUser(conn, msg)

		case CREATE_ROOM:
			createRoom(conn, msg)

		case JOIN_ROOM:
			joinRoom(conn, msg)

		case GET_LIST_ROOM:
			getListRoom(conn, msg)

		case SEND_IN_ROOM:
			sendRoom(conn, msg)

		/* case KICK_USER:
		kick_user(conn, msg) */

		case DISCONNECT:
			disconUser(conn, msg)

		case ADD_USER:
			addUser(conn, msg.RoomName, msg.Data)
		}

	}

}


//Function to create a room 
func createRoom(conn net.Conn, msg *Message) {
	//Generating a pseudo-random string 
	name := RandStringBytes(10)

	//delete space 
	msg.Data = strings.TrimSpace(msg.Data)

	//since our string comes from the user in encoded form, hex.EncodeToString , we need to decode it and get the bytes in the output 
	dataBytes, _ := hex.DecodeString(msg.Data)

	//Decrypting with AES 
	msg.Data = string(gooper.DecryptAES(usersSessKey[msg.NickName], dataBytes))

	msg.Data = strings.TrimSpace(msg.Data)
	//Dividing the string by the symbol to get a list of users who will be in this room 
	message := strings.Split(msg.Data, ",")

	//Create a new room structure object and put the data into it 
	room := new(Room)
	room.owner = conn
	room.usersRoom = make(map[net.Conn]bool)

	var pubKeys string

	//We enroll room members, add a room name for each room, and take their public keys 
	for _, x := range message {
		if x != "" {
			room.usersRoom[users[x].connection] = false
			users[x].ListRoom = append(users[x].ListRoom, name)
			pubKeys += string(users[x].PubKey) + ","

		}
	}

	rooms[name] = room

	msg = NewMessage(HANDSHAKE, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(pubKeys))), name, NickServer)

	//send message
	SendMessage(conn, msg)

	msg = ReadMessage(conn)

	dataBytes, _ = hex.DecodeString(msg.Data)

	msg.Data = string(gooper.DecryptAES(usersSessKey[msg.NickName], dataBytes))

	keys := strings.Split(msg.Data, ",")

	//we have obtained an encrypted session key for each user, now we need to write them into the user structure  
	for i := 0; i < len(keys)-1; i++ {
		if keys[i] != "" {
			users[message[i]].SessKeys = make(map[string]string)
			users[message[i]].SessKeys[name] = keys[i]

		}
	}
	
}

//function to connect to the room 
func joinRoom(conn net.Conn, msg *Message) {
	//Check if the room that the user sent us exists 
	_, state := rooms[msg.RoomName].usersRoom[conn]
	if state {
		//make his status active 
		rooms[msg.RoomName].usersRoom[conn] = true

		msg = NewMessage(HANDSHAKE, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(users[msg.NickName].SessKeys[msg.RoomName]))), "", NickServer)

		SendMessage(conn, msg)
	} else {
		//If there is no such room, we return the message 
		message := fmt.Sprintf("%s : There is no such room", NickServer)
		msg = NewMessage(ERROR, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(message))), "", NickServer)

		SendMessage(conn, msg)
	}
}

//user registration function 
func regUser(conn net.Conn, msg *Message) {
	//check if the nickname is busy 
	_, state := users[msg.NickName]
	if state {
		msg = NewMessage(ERROR, fmt.Sprintf("%s : The username is already taken", NickServer), "", NickServer)

		SendMessage(conn, msg)

	} else {
		//Create a new user object and enter all its data 
		user := new(User)
		user.connection = conn
		user.PubKey = []byte(msg.Data)
		users[msg.NickName] = user
		usersConn[conn] = msg.NickName

		msg = NewMessage(HANDSHAKE, gooper.PublicKeyToString(PublickKey), "", NickServer)

		SendMessage(conn, msg)

		msg = ReadMessage(conn)

		dataBytes, _ := hex.DecodeString(msg.Data)

		usersSessKey[msg.NickName] = gooper.DecryptRSA(PrivateKey, dataBytes)

		message := fmt.Sprintf("%s : Successful registration", NickServer)

		msg = NewMessage(MSG, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(message))), "", NickServer)

		SendMessage(conn, msg)

	}
}

//send a list of rooms to the user 
func getListRoom(conn net.Conn, msg *Message) {
	list := strings.Join(users[msg.NickName].ListRoom, ",")

	list = fmt.Sprintf("%s : %s", NickServer, list)

	msg = NewMessage(MSG, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(list))), "", NickServer)

	SendMessage(conn, msg)
}

//This function is only for forwarding messages in the room 
func sendRoom(conn net.Conn, msg *Message) {
	for item := range rooms[msg.RoomName].usersRoom {
		if item != conn {
			SendMessage(item, msg)
		}
	}
}

//function to remove the room  
func deleteRoom(conn net.Conn, name string) {
	if rooms[name].owner == conn {
		delete(rooms, name)
	}
}

//Adding a user to an existing room 
func addUser(conn net.Conn, name string, nickname string) {
	if rooms[name].owner == conn {

		_, state := users[nickname]
		if state {
			rooms[name].usersRoom[users[nickname].connection] = false
			users[nickname].ListRoom = append(users[nickname].ListRoom, name)
			msg := NewMessage(HANDSHAKE, string(users[nickname].PubKey), name, NickServer)

			SendMessage(conn, msg)

			msg = ReadMessage(conn)

			users[nickname].SessKeys = make(map[string]string)

			users[nickname].SessKeys[name] = msg.Data

		} else {
			message := fmt.Sprintf("%s: There is no such user ", NickServer)
			msg := NewMessage(ERROR, hex.EncodeToString(gooper.EncryptAES(usersSessKey[nickname], []byte(message))), name, NickServer)
			SendMessage(conn, msg)
		}
	}
}

//function is needed to disconnect the user from the room 
func disconUser(conn net.Conn, msg *Message) {
	rooms[msg.RoomName].usersRoom[conn] = false
	msg = NewMessage(DISCONNECT, "", "", "")
	SendMessage(conn, msg)
}
