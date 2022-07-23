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
	yaml "gopkg.in/yaml.v3"
)

type conf struct {
	Editor string
}

func main() {
	var (
		file  string
		read  bool
		write bool
		edit  bool
		help  bool
	)
	flag.StringVar(&file, "f", "", "Specify the file")
	flag.BoolVar(&read, "r", false, "Decrypt file and read")
	flag.BoolVar(&write, "w", false, "Write to file and encrypt")
	flag.BoolVar(&edit, "e", false, "Enter editing mode")
	flag.BoolVar(&help, "h", false, "Displays this help panel")
	flag.Parse()

	app(file, help, read, write, edit)
}

func app(file string, help, read, write, edit bool) {
	cfg, err := readConf("config.yaml")
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) < 2 || help {
		flag.VisitAll(func(flag *flag.Flag) {
			format := "\t-%s:\t %s (Default: '%s')\n"
			fmt.Printf(format, flag.Name, flag.Usage, flag.DefValue)
		})
		fmt.Printf("\nExample: ./notify -f mynote -w\n")
	}
	if file != "" && write {
		if _, err = os.Stat(file); errors.Is(err, os.ErrNotExist) {
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
			OpenEditor(file, cfg)
			Encrypt(file, file, key[:])
			return
		} else {
			fmt.Printf("There already exists a file with such a name, proceed anyways? (this will encrypt all the data in that file) y/N: ")
			ans := ""
			fmt.Scanf("%s", &ans)
			if ans == "Y" || ans == "y" {
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
				OpenEditor(file, cfg)
				Encrypt(file, file, key[:])
				return
			} else {
				return
			}
		}
	}

	if file != "" && edit {
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

		OpenEditor(tmpFile.Name(), cfg)
		Encrypt(tmpFile.Name(), file, key[:])
		os.Remove(tmpFile.Name())
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
		OpenEditor(tmpFile.Name(), cfg)
		os.Remove(tmpFile.Name())
	}

}

func readConf(filename string) (*conf, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c := &conf{}
	err = yaml.Unmarshal(buf, c)
	if err != nil {
		return nil, fmt.Errorf("in file %q: %v", filename, err)
	}

	return c, nil
}

func ReturnErr(err error) {
	if err != nil {
		fmt.Printf("%v", err)
		return
	}
}
func OpenEditor(file string, conf *conf) {
	path, err := exec.LookPath(conf.Editor)
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
