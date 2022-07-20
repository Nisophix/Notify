package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	"golang.org/x/crypto/ssh/terminal"
)

var (
	file  string
	read  bool
	write bool
	help  bool
)

func init() {
	flag.StringVar(&file, "f", "", "Specify the file")
	flag.BoolVar(&read, "r", false, "Decrypt and read")
	flag.BoolVar(&write, "w", false, "Write and encrypt")
	flag.BoolVar(&help, "h", false, "Displays this help panel")

}

func main() {
	flag.Parse()
	if len(os.Args) < 2 || help {
		DisplayHelp()
	}
	if file != "" && write {
		if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
			//if an encrypted file with this name does NOT exist, then create one
			//and enter editing mode
			fmt.Print("Create a password: ")
			pass1 := PromptPassword()
			fmt.Print("\nRepeat the password: ")
			pass2 := PromptPassword()
			if bytes.Compare(pass1, pass2) != 0 {
				fmt.Println("\nThe passwords don't match, try again.")
				os.Exit(1)
			}
			fmt.Println()
			key := sha256.Sum256(pass1)
			OpenEditor(file)
			Encrypt(file, file, key[:])
		} else {
			//If an encrypted file with this name exists then enter editing mode
			fmt.Print("Password: ")
			pass := PromptPassword()
			key := sha256.Sum256(pass)
			data := Decrypt(file, key[:])
			tmpFile := SaveTmp(data)
			OpenEditor(tmpFile.Name())
			Encrypt(tmpFile.Name(), file, key[:])
			os.Remove(tmpFile.Name())
		}
	}
	if file != "" && read {
		fmt.Print("Password: ")
		pass := PromptPassword()
		key := sha256.Sum256(pass)
		data := Decrypt(file, key[:])
		tmpFile := SaveTmp(data)
		OpenEditor(tmpFile.Name())
	}
}

func OpenEditor(file string) {
	path, err := exec.LookPath("vim")
	cmd := exec.Command(path, file)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		fmt.Printf("Start failed: %s", err)
	}
	err = cmd.Wait()
}
func SaveTmp(data []byte) *os.File {
	tmpDir := os.TempDir()
	tmpFile, err := ioutil.TempFile(tmpDir, "tempFilePrefix")
	if err != nil {
		panic(err.Error())
	}
	err = ioutil.WriteFile(tmpFile.Name(), data, 0777)
	if err != nil {
		log.Panic(err)
	}
	fmt.Printf("\nDecrypted contents saved to %s\n", tmpFile.Name())
	return tmpFile
}
func Decrypt(src string, key []byte) []byte {
	enc, err := ioutil.ReadFile(src)
	if err != nil {
		panic(err.Error())
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return []byte(plaintext)
}
func Encrypt(src, dst string, key []byte) []byte {
	plaintext, err := ioutil.ReadFile(src)
	if err != nil {
		log.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Panic(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	err = ioutil.WriteFile(dst, ciphertext, 0777)
	if err != nil {
		log.Panic(err)
	}
	return ciphertext
}
func DisplayHelp() {
	flag.VisitAll(func(flag *flag.Flag) {
		format := "\t-%s:\t %s (Default: '%s')\n"
		fmt.Printf(format, flag.Name, flag.Usage, flag.DefValue)
	})
	fmt.Println()
	fmt.Println("Write a file:\tNotify -f filename -w")
	fmt.Println("Read a file:\tNotify -f filename -r")
}

func PromptPassword() []byte {
	password, err := terminal.ReadPassword(0)
	if err != nil {
		log.Fatal(err)
	}
	return password
}
