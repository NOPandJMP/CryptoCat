# Русская версия

Я хотел бы представить вам свой чат Crypto Cat v1.0. Технологии реализации: передача данных по модели tcp/ip, метод шифрования RSA для "рукопожатия", метод шифрование AES для безопасной передачи данных (чтобы злоумышленник не смог увидеть сообщение в открытом виде).
В наше время существует большое количество различных социальных сетей. В России это:

- вконтакте
- однокласники
- мейл ру

За рубежом:

- facebook
- instagram
- youtube
- Yahoo! 360
- AIM pages

Можно продолжать еще долго. Но все они небезопасны, в первую очередь потому, что для выхода на рынок какой-либо страны, они вынуждены использовать стандарты шифрования, которые обязательны в данной стране.

Как пример, в России есть метод шифрования "Кузнечик", который был разработан ФСБ, он в априори считается не безопасным, но такие методы использует не только России, в Америки это использует АНБ, в любой момент по запросу компания будет вынуждена выдать все данные по определённому пользователю, либо же если использовать методы шифрования из стандартов, спецслужбам даже не нужны никакие запросы, они создают эти методы шифрования изначально с уязвимостями, поэтому они могут сами смотреть и получать информацию, когда им потребуется.
Я считаю, что каждый человек имеет право на конфиденциальность переписки, но в наше время это почти невозможно.

![alt text](https://github.com/NOPandJMP/CryptoCat/blob/master/img/rus.jpg?raw=true)

Поэтому я решил сделать свой небольшой чат.

# Как же работает мой чат ?

Сначала, при запуске, у нас генерируется два ключа - публичный и приватный, это ключи RSA (сейчас безопасным является длина ключа 2048 бит), они нам нужны только для "рукопожатия", чтобы передать сеансовый ключ шифрования .

```golang
var PrivateKey, PublickKey = GenerateKeyPair(2048)

//Function for creating RSA key pairs
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		LogFatal(err)
	}
	return privkey, &privkey.PublicKey
}
```

Пример функций шифрорвания и дешифрования для RSA

```golang
// Used RSA(OAEP).
func EncryptRSA(pub *rsa.PublicKey, data []byte) []byte {
	data, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
	if err != nil {
		return nil
	}
	return data
}

// Used RSA(OAEP).
func DecryptRSA(priv *rsa.PrivateKey, data []byte) []byte {
	data, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, data, nil)
	if err != nil {
		return nil
	}
	return data
}
```

Само рукопожатие.

```golang
//client
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

//server
func regUser(conn net.Conn, msg *Message) {
	_, state := users[msg.NickName]
	if state {
		msg = NewMessage(ERROR, fmt.Sprintf("%s : The username is already taken", NickServer), "", NickServer)

		SendMessage(conn, msg)

	} else {

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
```

После чего мы используем метод шифрования AES (мы будем использовать AES-256 , это означает что длина нашего ключа составляет 256 бит) для передачи данных между клиентом и сервером , а так же для шифрования передаваемой информации в чатах . AES считается достаточно криптостойким алгоритмом шифрования , есть всего две известные мне проблемы , такие как :

- Уязвимость к атакам по энергопотреблению на процедуру расширения ключа, что является весьма специфичным сценарием
- Определенные проблемы с расширением ключа «на лету»

Так же при каждом шифровании у нас будет генерироваться случайный вектор инициализации . Мы будем использовать режим CBC - один из режимов шифрования для симметричного блочного шифра с использованием механизма обратной связи. Каждый блок открытого текста (кроме первого) побитово складывается по модулю 2 (операция XOR) с предыдущим результатом шифрования .

```golang
func EncryptAES(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockSize := block.BlockSize()
	data = paddingPKCS5(data, blockSize)
	cipherText := make([]byte, blockSize+len(data))
	iv := cipherText[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blockSize:], data)
	return cipherText
}

// AES with CBC-mode.
func DecryptAES(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil
	}
	iv := data[:blockSize]
	data = data[blockSize:]
	if len(data)%blockSize != 0 {
		return nil
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	return unpaddingPKCS5(data)
}

```

После того как клиент связался с сервером и создали сеансовый ключ , пользователь может:

- создать комнату
- присоединиться к комнате
- получить список комнат , где находиться пользователь .

Когда пользователь создаёт комнату , он становитесь её администратором , генерирует сеансовый ключ , получает публичные ключи пользователей которых он пригласили, после чего сеансовый ключ шифруется публичными ключами пользователей и отправляет на сервер . Каждый пользователь при подключении получает сеансовый ключ комнаты , так же имя комнаты заноситься в список комнат пользователя .

```golang
//client

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


//server
func createRoom(conn net.Conn, msg *Message) {
	name := RandStringBytes(10)

	msg.Data = strings.TrimSpace(msg.Data)

	dataBytes, _ := hex.DecodeString(msg.Data)

	msg.Data = string(gooper.DecryptAES(usersSessKey[msg.NickName], dataBytes))

	msg.Data = strings.TrimSpace(msg.Data)
	message := strings.Split(msg.Data, ",")

	room := new(Room)
	room.owner = conn
	room.usersRoom = make(map[net.Conn]bool)

	var pubKeys string

	for _, x := range message {
		if x != "" {
			room.usersRoom[users[x].connection] = false
			users[x].ListRoom = append(users[x].ListRoom, name)
			pubKeys += string(users[x].PubKey) + ","

		}
	}

	rooms[name] = room

	msg = NewMessage(HANDSHAKE, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(pubKeys))), name, NickServer)

	SendMessage(conn, msg)

	msg = ReadMessage(conn)

	dataBytes, _ = hex.DecodeString(msg.Data)

	msg.Data = string(gooper.DecryptAES(usersSessKey[msg.NickName], dataBytes))

	keys := strings.Split(msg.Data, ",")

	for i := 0; i < len(keys)-1; i++ {
		if keys[i] != "" {
			users[message[i]].SessKeys = make(map[string]string)
			users[message[i]].SessKeys[name] = keys[i]

		}
	}

}

```

При запросе на получение списка комнат , пользователю отправляется список комнат в которых он находиться.

```golang
//client
func getListRoom(conn net.Conn) {

	msg := NewMessage(GET_LIST_ROOM, "", "", username)
	SendMessage(conn, msg)
	msg = ReadMessage(conn)
	data_byte, _ := hex.DecodeString(msg.Data)
	msg.Data = string(gooper.DecryptAES(serverSessKey, data_byte))
	fmt.Println(msg.Data)
}

//server
func getListRoom(conn net.Conn, msg *Message) {
	list := strings.Join(users[msg.NickName].ListRoom, ",")

	list = fmt.Sprintf("%s : %s", NickServer, list)

	msg = NewMessage(MSG, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(list))), "", NickServer)

	SendMessage(conn, msg)
}

```

- При подключении к комнате , вы должны знать её имя , а так же комната должна быть в списке у пользователя . Если даже вы введёте имя комнаты , которая существует , но вас нет в её списке , то вы получите ошибку . Если всё проходит успешно , то вы получить сеансовый ключ от комнату и станете активным пользователем , которому будут приходить сообщения .

```golang
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


//server
func joinRoom(conn net.Conn, msg *Message) {
	_, state := rooms[msg.RoomName].usersRoom[conn]
	if state {
		rooms[msg.RoomName].usersRoom[conn] = true

		msg = NewMessage(HANDSHAKE, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(users[msg.NickName].SessKeys[msg.RoomName]))), "", NickServer)

		SendMessage(conn, msg)
	} else {

		message := fmt.Sprintf("%s : There is no such room", NickServer)
		msg = NewMessage(ERROR, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(message))), "", NickServer)

		SendMessage(conn, msg)
	}
}

```

Когда вы войдёте в комнату , то у вас есть небольшой интерфейс :

- добавить пользователя
- отключиться
- исключить пользователя (сейчас в разработке)
- а так же передача функции администратора (сейчас в разработке) .

При добавлении пользователя вам нужно будет ввести его никнейм , получить публичный ключ ,зашифровать сеансовый ключ публичным ключом пользователя и отправить на сервер.

```golang
//client
func addUser(conn net.Conn, RoomName string) {
	fmt.Println("Pls enter name user")
	reader := bufio.NewReader(os.Stdin)
	user_name, err := reader.ReadString('\n')
	LogFatal(err)
	user_name = strings.TrimSpace(user_name)

	msg := NewMessage(ADD_USER, user_name, RoomName, username)

	SendMessage(conn, msg)

}

//server
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
```

Отключиться - вы перестанете слышать сообщения из комнаты и сможете выбрать другую , а так же переподключиться к комнате из которой вы вышли .

```golang
//client
func disconnect(conn net.Conn, RoomName string) {
	msg := NewMessage(DISCONNECT, "", RoomName, username)
	SendMessage(conn, msg)
}

//server
func disconUser(conn net.Conn, msg *Message) {
	rooms[msg.RoomName].usersRoom[conn] = false
	msg = NewMessage(DISCONNECT, "", "", "")
	SendMessage(conn, msg)
}

```

# Построение и запуск

Для того чтобы запустить или собрать чат, вам нужно прописать следущие команды в терминале :

```bash
#Построение сервера
go build -o server server.go header.go #Linux
GOOS=windows go build -o server.exe server.go header.go #Windows

#Построение клиента
go build -o client client.go header.go #Linux
GOOS=windows go build -o client.exe client.go header.go #Windows

#Запуск сервера
./server || ./server.exe


#Запуск клиента
./client || ./client.exe

```

```bash
#Запуск без сборки
go run server.go header.go
go run client.go header.go
```

# Уязвимости и проблема

Хотел бы поговорить об уязвимостях и проблемах моего чата :

- Имеется один централизованный сервер . Это является достаточно серьёзной уявзимостью , мы можем считать что сервер может быть скомпрометирован , и как пример он может подменить публичный ключ пользователя из комнаты на свой . Одно из решений - передавать публичные ключи через стороннее сервисы , но тут мы так же не можем быть уверены что сторонние сервисы будут безопасными . Так что эту проблему достаточно сложно решить .

- Нету функции исключения пользователя , сейчас я её разрабатываю . Почему мы не можем просто исключить его из комнаты ? Потому что данный пользователь уже имеет сеансовый ключ от комнаты . Так почему же мы не можем просто поменять сеансовый ключ ? Мы можем но это будет достаточно не удобно , поэтому проще пересоздать комнату , в которую мы занесём всех пользователей кроме исключенного , именно для этого нам нужна зеркальная мапа .

```golang
users = make(map[string]*User)
usersConn = make(map[net.Conn]string)
```

- Проблема что пользователи не могут занимать один и тот же никнейм . Да я считаю что это проблема , но если мы будем делать вход по никнейму и паролю , то пароль пользователя могут похитить , тогда получиться достаточно неприятная ситуация . Я думаю лучше создавать новый никнейм для одного сеанса , а так же проверять , если пользователь выходит из приложения , то никнейм становиться свободным через 24 часа , после чего он исчезает из всех комнат .

- Сервер может упасть из за некорректных данных , я нуждаюсь во многих проверках , поэтому это тоже будет исправляться .

Это пока что все известные мне ошибки и уязвимости , я буду поддерживать этот репозиторий , и так же будет версия для работы со скрытой сетью . Это будет как маленький сервис для большого проекта , создателем этого проекта является мой хороший друг и все вопросы можете задавать ему или мне .

Хотел бы напомнить насколько бы не была безопасна система , самая большая уязвимость сидит перед монитором.

Спасибо за уделённое время !

LINK : https://github.com/number571/gopeer


# English version

I would like to present you my Crypto Cat chat v1.0. Implementation technologies: data transmission via tcp/ip model, RSA encryption method for "handshake", AES encryption method for secure data transmission (so that attacker could not see the message in clear view).
Nowadays, there are a large number of different social networks. In Russia these are:

- vkontakte
- monoklassniki
- mail ru

Abroad:

- facebook
- instagram
- youtube
- Yahoo! 360
- AIM pages

We could go on for a long time. But all of them are insecure, primarily because in order to enter the market of any country, they are forced to use the encryption standards that are mandatory in that country.

As an example, in Russia, there is the "Grasshopper" encryption method, which was developed by the FSB, it is a priori considered not secure, but not only Russia uses such methods, in America the NSA uses it, at any time on request the company will be forced to give out all the data on a certain user, or if you use encryption methods from the standards, the intelligence services do not even need any requests, they create these encryption methods initially with vulnerabilities, so they can look and get information themselves when they need.
I think everyone has a right to privacy of correspondence, but it's almost impossible these days.

![alt text](https://github.com/NOPandJMP/CryptoCat/blob/master/img/eng.jpg?raw=true)

So I decided to make my own little chat room.

# So how does my chat room work?

At first, when starting, we generate two keys, one public and one private, they are RSA keys (the present safe key length is 2048 bit), we need them only for a "handshake", to send the session encryption key.

Vulnerabilities I know of in RSA:

- Generation of prime numbers.
- Secret exponent d
- Open exponent e

```golang
var PrivateKey, PublickKey = GenerateKeyPair(2048)

//Function for creating RSA key pairs
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		LogFatal(err)
	}
	return privkey, &privkey.PublicKey
}
```

Example of RSA encryption and decryption functions

```golang
// Used RSA(OAEP).
func EncryptRSA(pub *rsa.PublicKey, data []byte) []byte {
	data, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
	if err != nil {
		return nil
	}
	return data
}

// Used RSA(OAEP).
func DecryptRSA(priv *rsa.PrivateKey, data []byte) []byte {
	data, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, data, nil)
	if err != nil {
		return nil
	}
	return data
}
```

The handshake itself.

```golang
//client
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

//server
func regUser(conn net.Conn, msg *Message) {
	_, state := users[msg.NickName]
	if state {
		msg = NewMessage(ERROR, fmt.Sprintf("%s : The username is already taken", NickServer), "", NickServer)

		SendMessage(conn, msg)

	} else {

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
```

After that we use the AES encryption method (we will use AES-256, this means that the length of our key is 256 bits) to transfer data between the client and the server and to encrypt the information sent in chats. AES is considered to be a fairly cryptographic encryption algorithm, there are only two problems that I know of, such as :

- Vulnerability to energy consumption attacks on the key expansion procedure, which is a very specific scenario
- Some problems with on the fly key expansion.

Also with each encryption we will have a random initialization vector generated . We will use CBC mode, one of the encryption modes for the symmetric block cipher, using a feedback mechanism. Each block of plaintext (except the first one) is bitwise added modulo 2 (XOR operation) with the previous encryption result .

```golang
func EncryptAES(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockSize := block.BlockSize()
	data = paddingPKCS5(data, blockSize)
	cipherText := make([]byte, blockSize+len(data))
	iv := cipherText[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blockSize:], data)
	return cipherText
}

// AES with CBC-mode.
func DecryptAES(key, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil
	}
	iv := data[:blockSize]
	data = data[blockSize:]
	if len(data)%blockSize != 0 {
		return nil
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	return unpaddingPKCS5(data)
}

```

After the client has contacted the server and created a session key, the user can:

- create a room
- join a room
- retrieve a list of the rooms where the user is located.

When the user creates a room, he becomes the room administrator, generates a session key, receives the public keys of the users he invited, then the session key is encrypted with the users public keys and sent to the server. Each user on connection gets a session key of the room , also the name of the room is written in the list of user's rooms .

```golang
//client

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


//server
func createRoom(conn net.Conn, msg *Message) {
	name := RandStringBytes(10)

	msg.Data = strings.TrimSpace(msg.Data)

	dataBytes, _ := hex.DecodeString(msg.Data)

	msg.Data = string(gooper.DecryptAES(usersSessKey[msg.NickName], dataBytes))

	msg.Data = strings.TrimSpace(msg.Data)
	message := strings.Split(msg.Data, ",")

	room := new(Room)
	room.owner = conn
	room.usersRoom = make(map[net.Conn]bool)

	var pubKeys string

	for _, x := range message {
		if x != "" {
			room.usersRoom[users[x].connection] = false
			users[x].ListRoom = append(users[x].ListRoom, name)
			pubKeys += string(users[x].PubKey) + ","

		}
	}

	rooms[name] = room

	msg = NewMessage(HANDSHAKE, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(pubKeys))), name, NickServer)

	SendMessage(conn, msg)

	msg = ReadMessage(conn)

	dataBytes, _ = hex.DecodeString(msg.Data)

	msg.Data = string(gooper.DecryptAES(usersSessKey[msg.NickName], dataBytes))

	keys := strings.Split(msg.Data, ",")

	for i := 0; i < len(keys)-1; i++ {
		if keys[i] != "" {
			users[message[i]].SessKeys = make(map[string]string)
			users[message[i]].SessKeys[name] = keys[i]

		}
	}

}

```

When requested to receive a list of rooms, the user is sent a list of rooms in which he is

```golang
//client
func getListRoom(conn net.Conn) {

	msg := NewMessage(GET_LIST_ROOM, "", "", username)
	SendMessage(conn, msg)
	msg = ReadMessage(conn)
	data_byte, _ := hex.DecodeString(msg.Data)
	msg.Data = string(gooper.DecryptAES(serverSessKey, data_byte))
	fmt.Println(msg.Data)
}

//server
func getListRoom(conn net.Conn, msg *Message) {
	list := strings.Join(users[msg.NickName].ListRoom, ",")

	list = fmt.Sprintf("%s : %s", NickServer, list)

	msg = NewMessage(MSG, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(list))), "", NickServer)

	SendMessage(conn, msg)
}

```

- When connecting to a room, you must know its name, and the room must be on the user's list. Even if you enter a name for a room that exists and you are not on the list, you will get an error. If all goes well, you will receive a session key for the room and become an active user, who will receive messages.

```golang
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


//server
func joinRoom(conn net.Conn, msg *Message) {
	_, state := rooms[msg.RoomName].usersRoom[conn]
	if state {
		rooms[msg.RoomName].usersRoom[conn] = true

		msg = NewMessage(HANDSHAKE, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(users[msg.NickName].SessKeys[msg.RoomName]))), "", NickServer)

		SendMessage(conn, msg)
	} else {

		message := fmt.Sprintf("%s : There is no such room", NickServer)
		msg = NewMessage(ERROR, hex.EncodeToString(gooper.EncryptAES(usersSessKey[msg.NickName], []byte(message))), "", NickServer)

		SendMessage(conn, msg)
	}
}

```

When you enter a room , you have a small interface :

- add user
- sign out
- expel user (now in development)
- as well as the administrator function (currently in development).

When adding a user you will have to enter his nickname, get a public key, encrypt the session key with the user's public key and send it to the server.

```golang
//client
func addUser(conn net.Conn, RoomName string) {
	fmt.Println("Pls enter name user")
	reader := bufio.NewReader(os.Stdin)
	user_name, err := reader.ReadString('\n')
	LogFatal(err)
	user_name = strings.TrimSpace(user_name)

	msg := NewMessage(ADD_USER, user_name, RoomName, username)

	SendMessage(conn, msg)

}

//server
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
```

Disconnect - you will stop hearing messages from the room and can choose another one, as well as reconnect to the room you left.

```golang
//client
func disconnect(conn net.Conn, RoomName string) {
	msg := NewMessage(DISCONNECT, "", RoomName, username)
	SendMessage(conn, msg)
}

//server
func disconUser(conn net.Conn, msg *Message) {
	rooms[msg.RoomName].usersRoom[conn] = false
	msg = NewMessage(DISCONNECT, "", "", "")
	SendMessage(conn, msg)
}

```

# Build and Run

In order to start or build a chat room, you need to type the following commands in the terminal :

```bash
#Build server
go build -o server server.go header.go #Linux
GOOS=windows go build -o server.exe server.go header.go #Windows

#Build client
go build -o client client.go header.go #Linux
GOOS=windows go build -o client.exe client.go header.go #Windows

#Server startup
./server || ./server.exe


#Client
./client || ./client.exe

```

```bash
#Run without building
go run server.go header.go
go run client.go header.go
```

# Vulnerabilities and problems

I would like to talk about vulnerabilities and problems with my chat room :

- There is one centralized server . This is a serious vulnerability, we can think that the server can be compromised, and for example it can swap a user's public key from the room with his own. One solution is to send public keys via third party services , but we can not be sure if the third party services will be safe either. It is difficult to solve this problem.

- There is no function to exclude users, I am working on it now. Why can't we just exclude him from the room? Because this user already has a session key to the room . So why can't we just change the session key? We can, but it would be rather uncomfortable, so it's easier to recreate a room where we put all users except the excluded one, that's why we need a mirror map.

```golang
users = make(map[string]*User)
usersConn = make(map[net.Conn]string)
```

- The problem is that users can't occupy the same nickname . Yes I think this is a problem, but if we do a login with nickname and password, then user's password could be stolen, then it would be quite unpleasant situation. I think it is better to create a new nickname for one session, as well as to check if the user leaves the application, the nickname becomes free after 24 hours, after which it disappears from all rooms.

- The server can crash because of incorrect data, I need a lot of checks, so this too will be corrected.

This is so far all the bugs and vulnerabilities I know about, I will support this repository , and there will also be a version to work with the hidden network . It will be like a small service for a big project, the creator of this project is my good friend and all questions are welcome to ask him or me.

I would like to remind you that no matter how secure the system is, the biggest vulnerability sits in front of the monitor.

Thanks for your time!

LINK : https://github.com/number571/gopeer
