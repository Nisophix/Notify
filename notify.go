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

func main() {
	var (
		file  string
		read  bool
		write bool
		help  bool
	)
	flag.StringVar(&file, "f", "", "Specify the file")
	flag.BoolVar(&read, "r", false, "Decrypt and read")
	flag.BoolVar(&write, "w", false, "Write and encrypt")
	flag.BoolVar(&help, "h", false, "Displays this help panel")
	flag.Parse()

	app(file, help, write, read)
}

func app(file string, help, write, read bool) {
	if len(os.Args) < 2 || help {
		flag.VisitAll(func(flag *flag.Flag) {
			format := "\t-%s:\t %s (Default: '%s')\n"
			fmt.Printf(format, flag.Name, flag.Usage, flag.DefValue)
		})
		fmt.Println()
		fmt.Println("Write a file:\tNotify -f filename -w")
		fmt.Println("Read a file:\tNotify -f filename -r")
	}
	if file != "" && write {
		if _, err := os.Stat(file); errors.Is(err, os.ErrNotExist) {
			//if an encrypted file with this name does NOT exist, then create one
			//and enter editing mode
			fmt.Printf("Create a password: ")
			pass1, err := PromptPassword()
			ReturnErr(err)
			fmt.Printf("\nRepeat the password: ")
			pass2, err := PromptPassword()
			ReturnErr(err)
			if bytes.Compare(pass1, pass2) != 0 {
				fmt.Printf("\nThe passwords don't match, try again.\n")
				return
			}
			fmt.Println()
			key := sha256.Sum256(pass1)
			OpenEditor(file)
			Encrypt(file, file, key[:])
		} else {
			//If an encrypted file with this name exists then enter editing mode
			fmt.Print("Password: ")
			pass, err := PromptPassword()
			ReturnErr(err)

			key := sha256.Sum256(pass)
			data, err := Decrypt(file, key[:])
			if err != nil {
				log.Fatal(err)
			}

			tmpFile, err := SaveTmp(data)
			ReturnErr(err)

			OpenEditor(tmpFile.Name())
			Encrypt(tmpFile.Name(), file, key[:])
			os.Remove(tmpFile.Name())
		}
	}
	if file != "" && read {
		fmt.Print("Password: ")
		pass, err := PromptPassword()
		ReturnErr(err)

		key := sha256.Sum256(pass)
		data, err := Decrypt(file, key[:])
		if err != nil {
			log.Fatal(err)
		}

		tmpFile, err := SaveTmp(data)
		ReturnErr(err)

		OpenEditor(tmpFile.Name())
	}

}

func ReturnErr(err error) {
	if err != nil {
		fmt.Printf("%v", err)
		return
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
func SaveTmp(data []byte) (*os.File, error) {
	tmpDir := os.TempDir()
	tmpFile, err := ioutil.TempFile(tmpDir, "DecryptedNote")
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(tmpFile.Name(), data, 0777)
	if err != nil {
		return nil, err
	}
	fmt.Printf("\nDecrypted contents saved to %s\n", tmpFile.Name())
	return tmpFile, nil
}
func Decrypt(src string, key []byte) ([]byte, error) {
	enc, err := ioutil.ReadFile(src)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return []byte(plaintext), nil
}
func Encrypt(src, dst string, key []byte) ([]byte, error) {
	plaintext, err := ioutil.ReadFile(src)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	err = ioutil.WriteFile(dst, ciphertext, 0777)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func PromptPassword() ([]byte, error) {
	password, err := terminal.ReadPassword(0)
	if err != nil {
		return nil, err
	}
	return password, nil
}
