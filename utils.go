package utils

import (
	"bytes"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	gooper "github.com/Number571/gopeer"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"time"
)

//Ending for our transmitted message
var eof = []byte{'\r', '\n', '\r', '\n'}

//enum for our message , to distribute requests

const (
	Empty         = byte(0x0)
	CREATE_ROOM   = byte(0x1)
	JOIN_ROOM     = byte(0x2)
	DELETE_ROOM   = byte(0x3)
	ERROR         = byte(0x4)
	DISCONNECT    = byte(0x5)
	SEND_IN_ROOM  = byte(0x6)
	MSG           = byte(0x7)
	KICK_USER     = byte(0x8)
	ADD_USER      = byte(0x9)
	HANDSHAKE     = byte(0x10)
	GET_LIST_ROOM = byte(0x11)
	REG           = byte(0x12)
)

const (
	ColorReset = "\033[0m"

	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

//The structure of our transmitted message
type Message struct {
	Option   byte
	Data     []byte
	NickName string
	RoomName string
}

//Sending a message
func SendMessage(conn net.Conn, msg *Message) {
	conn.Write(bytes.Join([][]byte{SerializeMessage(msg), eof}, []byte{}))
}

func SendMessageWhithEncrypt(conn net.Conn, msg *Message, seesKey []byte) {
	msg.Data = gooper.EncryptAES(seesKey, msg.Data)
	conn.Write(bytes.Join([][]byte{SerializeMessage(msg), eof}, []byte{}))
}

//Creating a new message object
func NewMessage(option byte, data []byte, roomName string, username string) *Message {
	msg := new(Message)
	msg.Option = option
	msg.Data = data
	msg.NickName = username
	msg.RoomName = roomName
	return msg
}

//error handling
func PrintError(err error) {
	fmt.Println(ColorGreen, "Received error , description: ", ColorRed, err)
	fmt.Println(ColorReset)
}

//Creating an RSA key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(cryptoRand.Reader, bits)
	if err != nil {
		PrintError(err)
	}
	return privkey, &privkey.PublicKey
}

//Creating a session key using cryptographic random
func GenerateSessionKey(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil
	}

	return b
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

func SavePrivateServerKey(key []byte) {
	privateKey, publicKey := GenerateKeyPair(2048)
	fmt.Println("Pls save publicKey")
	fmt.Println("PublicKey : ", gooper.PublicKeyToString(publicKey))
	key = gooper.HashSum(key)
	f, err := os.Create("privateKey.txt")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer f.Close()
	f.Write(gooper.EncryptAES(key, gooper.PrivateKeyToBytes(privateKey)))
}

func LoadPrivateServerKey(key []byte) (*rsa.PrivateKey, error) {
	key = gooper.HashSum(key)
	text, err := ioutil.ReadFile("privateKey.txt")
	if err != nil {
		PrintError(err)
		os.Exit(1)
	}
	decryptData := gooper.DecryptAES(key, text)
	if decryptData == nil {
		return nil, fmt.Errorf("Invalid key")
	}

	return gooper.BytesToPrivateKey(decryptData), nil

}

func (m Message) PrintMessage(key []byte) {
	fmt.Println(ColorGreen, m.NickName, ColorReset, " : ", string(gooper.DecryptAES(key, m.Data)))
}

func StringToBytes(str string) []byte {
	return []byte(str)
}

//List of characters , to create a random string
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

//Function for creating a random string
func RandStringBytes(n int) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[r.Intn(len(letterBytes))]
	}
	return string(b)
}

const PublickServerKey = "MIIBCgKCAQEAro_zPr-gO-eW5_euayhNFvLbWDZlkaW86h8MGokdvx4RRRFabl1nxiCSC-8i4GkSf9V-OGaJdZOT4ZgPicArsFRelfvxHMPd5o8P-l6cm0vkPL8w0M96ywDs_1TIpXL5Mqz67uP_QxhtmF3ApvK38d4emo3b2PAQb2mKARCY1KSiKo_RdQo0YeHQB3onKX5F1dCkZl10GHXM3sNeX8CmbH7bX6TOIDdYaiG-s1UwCigw3YMKTblycbZjjrQ2UcB5WtYMf1EPvxytFeNvoOQomXwjelDJv-MFvSi4MXPRhGJzBl6d_7EwIPXZk8NNwauOXccuWq9cEyVvVLsIO2hkPQIDAQAB"
