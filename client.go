package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	gooper "github.com/Number571/gopeer"
)

var (
	username                string
	message                 string
	RoomName               string
	sesion_keys             = make(map[string][]byte)
	PrivateKey, PublickKey = GenerateKeyPair(2048)
	readStat             = make(chan bool)
	serverSessKey, err    = GenerateSessionKey(32)
)


func main() {
	//Connecting to the server 
	connection, err := net.Dial("tcp", "localhost:8080")
	LogFatal(err)

	defer connection.Close()

	handleConn(connection)

	fmt.Println("Exit from Crypto Cat 1.0")
}


//the function is to read messages from the room when we are in it 
func read(conn net.Conn) {
exit:
	for {
		//read message
		msg := ReadMessage(conn)

		if msg == nil {
			fmt.Println("Error listening")
			break
		}

		switch msg.SwitchFlag {
		case HANDSHAKE:
			crypt_session_key := hex.EncodeToString(gooper.EncryptRSA(gooper.StringToPublicKey(msg.Data), sesion_keys[msg.RoomName]))
			msg = NewMessage(HANDSHAKE, crypt_session_key, msg.RoomName, username)

			SendMessage(conn, msg)

			continue

		case DISCONNECT:
			if msg.NickName == username {
				fmt.Println("exit from room , disconnect")
				break exit
			}
		case KICK_USER:
			fmt.Println("exit from room , room update")
			break exit

		}

		//decode hex string 
		data_byte, err := hex.DecodeString(msg.Data)
		LogFatal(err)

		//print decypt message
		fmt.Printf("%s", string(gooper.DecryptAES(sesion_keys[msg.RoomName], data_byte)))

	}

}

//function for generating user requests  
func handleConn(conn net.Conn) {
	reg(conn)
exit:
	for {
		reader := bufio.NewReader(os.Stdin)
		message, err := reader.ReadString('\n')
		LogFatal(err)
		switch message {
		case "--help\n":
			fmt.Println("--list_room: Displays a list of rooms that you are a member of\n")
			fmt.Println("--createRoom: Create new room\n")
			fmt.Println("--joinRoom: Join in room\n")
			fmt.Println("--clear: clear console\n")
			fmt.Println("--exit: exit from app\n")

		case "--list_room\n":
			getListRoom(conn)

		case "--create_room\n":
			createRoom(conn)

		case "--join_room\n":
			joinRoom(conn)

		case "--exit\n":
			break exit

		case "--clear\n":
			if runtime.GOOS == "windows" {
				cmd := exec.Command("cmd", "/c", "cls")
				cmd.Stdout = os.Stdout
				cmd.Run()
			} else {
				cmd := exec.Command("clear")
				cmd.Stdout = os.Stdout
				cmd.Run()
			}

		default:
			fmt.Println("Error command\nType --help to see all the commands ")

		}
	}
}

//user registration feature 
func reg(conn net.Conn) {
	for {
		fmt.Println("Pls enter your username")
		reader := bufio.NewReader(os.Stdin)
		username, err = reader.ReadString('\n')
		username = strings.TrimSpace(username)
		msg := NewMessage(REG, gooper.PublicKeyToString(PublickKey), "", username)

		SendMessage(conn, msg)

		msg = ReadMessage(conn)

		if msg.SwitchFlag == ERROR {
			fmt.Printf("%s \n", msg.Data)
			continue
		}

		msg = NewMessage(HANDSHAKE, hex.EncodeToString(gooper.EncryptRSA(gooper.StringToPublicKey(msg.Data), serverSessKey)), "", username)

		SendMessage(conn, msg)

		msg = ReadMessage(conn)

		data_byte, err := hex.DecodeString(msg.Data)

		LogFatal(err)

		fmt.Printf("%s \n", string(gooper.DecryptAES(serverSessKey, data_byte)))

		if msg.SwitchFlag == MSG {
			break
		}
	}
}


//function to create a room 
func createRoom(conn net.Conn) {
	fmt.Println("Enter pls nickanme user \nExample: alice,bob \n")

	reader := bufio.NewReader(os.Stdin)
	nickanmes, err := reader.ReadString('\n')
	LogFatal(err)

	nickanmes = username + "," + nickanmes

	msg := NewMessage(CREATE_ROOM, hex.EncodeToString(gooper.EncryptAES(serverSessKey, []byte(nickanmes))), "", username)

	SendMessage(conn, msg)

	msg = ReadMessage(conn)

	data_byte, _ := hex.DecodeString(msg.Data)
	msg.Data = string(gooper.DecryptAES(serverSessKey, data_byte))

	msg.Data = strings.TrimSpace(msg.Data)
	message := strings.Split(msg.Data, ",")

	seesion_key, _ := GenerateSessionKey(32)

	var text string
	for _, key := range message {

		if key != "" {
			text += hex.EncodeToString(gooper.EncryptRSA(gooper.StringToPublicKey(key), seesion_key))
			text += ","

		}
	}

	msg = NewMessage(MSG, hex.EncodeToString(gooper.EncryptAES(serverSessKey, []byte(text))), "", username)

	SendMessage(conn, msg)

}

//function to join the room 
func joinRoom(conn net.Conn) {
	reader := bufio.NewReader(os.Stdin)
	roomName, err := reader.ReadString('\n')
	LogFatal(err)
	fmt.Println("Pls enter name room")
	roomName = strings.TrimSpace(roomName)

	msg := NewMessage(JOIN_ROOM, "", roomName, username)
	SendMessage(conn, msg)
	msg = ReadMessage(conn)
	data_byte, err := hex.DecodeString(msg.Data)
	LogFatal(err)

	a := string(gooper.DecryptAES(serverSessKey, data_byte))

	data_byte, err = hex.DecodeString(a)

	sesion_keys[roomName] = gooper.DecryptRSA(PrivateKey, data_byte)
	go read(conn)
	write(conn, roomName)

}


func getListRoom(conn net.Conn) {

	msg := NewMessage(GET_LIST_ROOM, "", "", username)
	SendMessage(conn, msg)
	msg = ReadMessage(conn)
	data_byte, _ := hex.DecodeString(msg.Data)
	msg.Data = string(gooper.DecryptAES(serverSessKey, data_byte))
	fmt.Println(msg.Data)
}

//function for entering messages and sending them to the room 
func write(conn net.Conn, RoomName string) {
exit:
	for {
		reader := bufio.NewReader(os.Stdin)
		message, err := reader.ReadString('\n')
		if err != nil {
			LogFatal(err)
		}
		switch message {
		case "--help\n":
			fmt.Println("--disconnect: If you want to leave the chat room and go to another one, you can also return to this chat room\n")
			fmt.Println("--addUser: If you want to add a member, but this only works if you are the creator of the room\n")
			fmt.Println("--exit: Use only as a last resort if there were problems with listening to the room, or if you received a message about a room update \n")
			continue

		case "--disconnect\n":
			disconnect(conn, RoomName)
			break exit

		case "--add_user\n":
			addUser(conn, RoomName)
			continue

		case "--exit\n":
			break exit

		}

		message = fmt.Sprintf("%s: %s", username, message)
		msg := NewMessage(SEND_IN_ROOM, hex.EncodeToString(gooper.EncryptAES(sesion_keys[RoomName], []byte(message))), RoomName, username)
		SendMessage(conn, msg)

	}
}

//Adding a user to a room 
func addUser(conn net.Conn, RoomName string) {
	fmt.Println("Pls enter name user")
	reader := bufio.NewReader(os.Stdin)
	user_name, err := reader.ReadString('\n')
	LogFatal(err)
	user_name = strings.TrimSpace(user_name)

	msg := NewMessage(ADD_USER, user_name, RoomName, username)

	SendMessage(conn, msg)

}

//function disconnect from room
func disconnect(conn net.Conn, RoomName string) {
	msg := NewMessage(DISCONNECT, "", RoomName, username)
	SendMessage(conn, msg)
}
