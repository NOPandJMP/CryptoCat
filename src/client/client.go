package main

import (
	"bufio"
	"fmt"
	gooper "github.com/Number571/gopeer"
	utils "github.com/RAXandEAX/CryptoCat"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

var (
	Username               string
	message                string
	RoomName               string
	ServerSessKey          []byte
	RoomSessKEys           []byte
	PrivateKey, PublickKey = utils.GenerateKeyPair(2048)
	readStat               = make(chan bool)
)

func main() {
	//Connecting to the server
	connection, err := net.Dial("tcp", ":9090")
	if err != nil {
		utils.PrintError(err)
		os.Exit(1)
	}

	defer connection.Close()

	handleConn(connection)

	fmt.Println("Exit from Crypto Cat 1.0")
}

//the function is to read messages from the room when we are in it
func read(conn net.Conn) {

	for {
		//read message
		msg := utils.ReadMessage(conn)

		if msg == nil {
			fmt.Println("Error listening")
			break
		}

		msg.PrintMessage(ServerSessKey)

	}

}

//function for generating user requests
func handleConn(conn net.Conn) {
	handShake(conn)
exit:
	for {
		reader := bufio.NewReader(os.Stdin)
		command, err := reader.ReadString('\n')
		if err != nil {
			utils.PrintError(err)
			continue
		}

		switch command {
		case "--help\r\n":
			fmt.Println(utils.ColorGreen, "--list_room: Displays a list of rooms that you are a member of\n")
			fmt.Println(utils.ColorGreen, "--createRoom: Create new room\n")
			fmt.Println(utils.ColorGreen, "--joinRoom: Join in room\n")
			fmt.Println(utils.ColorGreen, "--clear: clear console\n")
			fmt.Println(utils.ColorGreen, "--exit: exit from app\n")
			fmt.Println(utils.ColorReset)

		/*case "--list_room\n":
		getListRoom(conn)*/

		/*case "--join_room\n":
		joinRoom(conn)*/

		case "--create_room\r\n":
			createRoom(conn)

		case "--exit\r\n":
			break exit

		case "--clear\r\n":
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
func handShake(conn net.Conn) {
	fmt.Println("Pls enter your username")
	reader := bufio.NewReader(os.Stdin)
	username, err := reader.ReadString('\n')
	if err != nil {
		utils.PrintError(err)
		os.Exit(1)
	}
	Username = strings.TrimSpace(username)
	msg := utils.NewMessage(utils.Empty, gooper.PublicKeyToBytes(PublickKey), "", username)
	utils.SendMessage(conn, msg)
	msg = utils.ReadMessage(conn)
	ServerSessKey = gooper.DecryptRSA(PrivateKey, msg.Data)

}

//function to create a room
func createRoom(conn net.Conn) {
	fmt.Println("Pls enter room name:")
	reader := bufio.NewReader(os.Stdin)
	roomName, err := reader.ReadString('\n')
	if err != nil {
		utils.PrintError(err)
	}
	RoomName = strings.TrimSpace(roomName)
	msg := utils.NewMessage(utils.CREATE_ROOM, nil, roomName, Username)
	utils.SendMessage(conn, msg)

	msg = utils.ReadMessage(conn)

	msg.PrintMessage(ServerSessKey)

}

func connectInRoom(conn net.Conn) {
	fmt.Println("Pls enter room name and room key\n Example test:AAAA")
	reader := bufio.NewReader(os.Stdin)
	data, err := reader.ReadString('\n')
	if err != nil {
		utils.PrintError(err)
		return
	}
	data = strings.TrimSpace(data)
	roomData := strings.Split(data, ":")
	if len(roomData) < 2 {
		utils.PrintError(fmt.Errorf("Incorrect format name:key"))
		return
	}

	msg := utils.NewMessage(utils.JOIN_ROOM, utils.StringToBytes(roomData[1]), roomData[0], Username)
	utils.SendMessageWhithEncrypt(conn, msg, ServerSessKey)

	msg = utils.ReadMessage(conn)
	if msg.Option != utils.ERROR {
		RoomSessKEys = gooper.DecryptAES(ServerSessKey, msg.Data)
	}
}

/*
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
*/
