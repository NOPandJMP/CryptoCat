package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log"
	"net"
)

//Ending for our transmitted message 
var eof = []byte{'\r', '\n', '\r', '\n'}

//enum for our message , to distribute requests 
const (
	CREATE_ROOM = iota + 1
	JOIN_ROOM
	DELETE_ROOM
	ERROR
	DISCONNECT
	SEND_IN_ROOM
	MSG
	KICK_USER
	ADD_USER
	HANDSHAKE
	GET_LIST_ROOM
	REG
)

//The structure of our transmitted message 
type Message struct {
	SwitchFlag int
	Data        string
	NickName    string
	RoomName    string
}

//Sending a message 
func SendMessage(conn net.Conn, msg *Message) {
	conn.Write(bytes.Join([][]byte{SerializeMessage(msg), eof}, []byte{}))
}

//Creating a new message object 
func NewMessage(_switchFlag int, data string, room_name string, username string) *Message {
	msg := new(Message)
	msg.SwitchFlag = _switchFlag
	msg.Data = data
	msg.NickName = username
	msg.RoomName = room_name
	return msg
}


//error handling
func LogFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

//Creating an RSA key pair 
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		LogFatal(err)
	}
	return privkey, &privkey.PublicKey
}

//Creating a session key using cryptographic random  
func GenerateSessionKey(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

//Function to convert from json to message object 
func DeserializeMessage(jsonData []byte) *Message {
	var pack = new(Message)
	err := json.Unmarshal(jsonData, pack)
	if err != nil {
		return nil
	}
	return pack
}

//Function to convert from message object to json  
func SerializeMessage(pack *Message) []byte {
	jsonData, err := json.MarshalIndent(pack, "", "\t")
	if err != nil {
		return nil
	}
	return jsonData
}

//Function to read the data that will come to us from the server 
func ReadMessage(conn net.Conn) *Message {
	var (
		message []byte
		size    = uint(0)
		buffer  = make([]byte, 4096)
	)
	for {
		length, err := conn.Read(buffer)
		if err != nil {
			return nil
		}
		size += uint(length)
		if size > (8 << 20) { // 8<<20 => 1 shifted 20 bits to the left, multiplied by 8, you get 8 MiB (8*(2^20)B = 8MiB)
			return nil
		}
		message = bytes.Join(
			[][]byte{
				message,
				buffer[:length],
			},
			[]byte{},
		)
		if bytes.Contains(message, eof) {
			message = bytes.Split(message, eof)[0]
			break
		}
	}
	return DeserializeMessage(message)
}
