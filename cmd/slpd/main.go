// main.go
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	crypt "github.com/coljac/slippard/internal/encryption"
)

const version = "0.1.1"

type KeyStore struct {
	keyPath   string
	storeFile string
	aesKey    []byte
	keyBlob   []byte
}

const tagDelimiter = "\x1B" // ESC character

func (k *KeyStore) writeLines(lines []string) error {
	// TODO: Create a backup of the file before writing in case of error
	file, err := os.OpenFile(k.storeFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	var writer strings.Builder
	for _, line := range lines {
		writer.WriteString(line + "\n")
	}
	cipherText, err := crypt.EncryptWithAES([]byte(writer.String()), k.aesKey)
	if err != nil {
		return err
	}
	if k.keyBlob == nil {
		k.keyBlob, err = crypt.EncryptWithSSHKey(k.aesKey, k.keyPath)
		if err != nil {
			return err
		}
	}

	// Write the length of the encrypted AES key (2 bytes)
	keyBlobLength := uint16(len(k.keyBlob))
	_, err = file.Write([]byte{byte(keyBlobLength >> 8), byte(keyBlobLength & 0xFF)})
	if err != nil {
		return err
	}

	// Write the encrypted AES key
	_, err = file.Write(k.keyBlob)
	if err != nil {
		return err
	}

	// Write the encrypted data
	_, err = file.Write([]byte(cipherText))
	if err != nil {
		return err
	}
	return nil
}

func (k *KeyStore) create() error {
	filename := k.storeFile
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	aesKey, err := crypt.MakeAesKey()
	if err != nil {
		return err
	}

	k.aesKey = aesKey

	defer file.Close()
	return nil
}

func (k *KeyStore) readLines() ([]string, error) {
	filename, keyPath := k.storeFile, k.keyPath
	var lines []string

	cipherText, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(cipherText) == 0 {
		key, err := crypt.MakeAesKey()
		if err != nil {
			return nil, err
		}
		k.aesKey = key
		return lines, nil
	}

	if len(cipherText) < 2 {
		return nil, fmt.Errorf("store file is corrupt: too short")
	}

	// Read the length of the encrypted AES key (2 bytes)
	keyBlobLength := int(cipherText[0])<<8 | int(cipherText[1])
	cipherText = cipherText[2:]

	if keyBlobLength > len(cipherText) {
		return nil, fmt.Errorf("store file is corrupt: key blob length %d exceeds data size %d", keyBlobLength, len(cipherText))
	}

	// Extract the encrypted AES key and the remaining ciphertext
	k.keyBlob, cipherText = cipherText[:keyBlobLength], cipherText[keyBlobLength:]
	k.aesKey, err = crypt.DecryptWithSSHKey(k.keyBlob, keyPath)
	if err != nil {
		return nil, fmt.Errorf("error decrypting AES key: %w", err)
	}

	plainText, err := crypt.DecryptWithAES(cipherText, k.aesKey)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	// iterate over lines in plainText
	scanner := bufio.NewScanner(strings.NewReader(plainText))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func (k *KeyStore) listKeys(filter, tag string) (string, error) {
	lines, err := k.readLines()
	if err != nil {
		return "", fmt.Errorf("error reading store file: %w", err)
	}
	var builder strings.Builder
	for _, line := range lines {
		if (filter == "" || strings.Contains(line, filter)) && (tag == "" || strings.HasSuffix(line, tagDelimiter+tag)) {
			key := strings.SplitN(line, "=", 2)[0]
			builder.WriteString(key + "\n")
		}
	}

	return builder.String(), nil
}

func (k *KeyStore) delKeyValue(key string) error {
	lines, err := k.readLines()
	if err != nil {
		return fmt.Errorf("error reading store file: %w", err)
	}

	for i, line := range lines {
		if strings.HasPrefix(line, key+"=") {
			lines = append(lines[:i], lines[i+1:]...)
			break
		}
	}

	err = k.writeLines(lines)
	if err != nil {
		return fmt.Errorf("error writing store file: %w", err)
	}

	return nil
}

func (k *KeyStore) dumpStore(tag string) (string, error) {
	lines, err := k.readLines()
	if err != nil {
		return "", fmt.Errorf("error reading store file: %w", err)
	}

	var trimmedLines []string
	for _, line := range lines {
		if tag == "" || strings.HasSuffix(line, tagDelimiter+tag) {
			if idx := strings.LastIndex(line, tagDelimiter); idx != -1 {
				line = line[:idx]
			}
			
			// Split the line into key and value
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				// Shell-escape the value with single quotes (escape embedded single quotes)
				escaped := strings.ReplaceAll(parts[1], "'", "'\"'\"'")
				trimmedLines = append(trimmedLines, parts[0]+"='"+escaped+"'")
			} else {
				trimmedLines = append(trimmedLines, line)
			}
		}
	}

	return strings.Join(trimmedLines, "\n"), nil
}

func (k *KeyStore) getKeyValue(key, tag string) (string, error) {
	lines, err := k.readLines()
	if err != nil {
		return "", fmt.Errorf("error reading store file: %w", err)
	}

	for _, line := range lines {
		if strings.HasPrefix(line, key+"=") {
			if tag == "" || strings.HasSuffix(line, tagDelimiter+tag) {
				return strings.TrimSuffix(strings.TrimPrefix(line, key+"="), tagDelimiter+tag), nil
			}
		}
	}

	return "", fmt.Errorf("key not found")
}

func (k *KeyStore) setKeyValue(key, value, tag string) error {
	lines, err := k.readLines()
	if err != nil {
		return fmt.Errorf("error reading store file: %w", err)
	}

	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, key+"=") {
			if tag == "" || strings.HasSuffix(line, tagDelimiter+tag) {
				lines[i] = key + "=" + value
				if tag != "" {
					lines[i] += tagDelimiter + tag
				}
				found = true
				break
			}
		}
	}

	if !found {
		newLine := key + "=" + value
		if tag != "" {
			newLine += tagDelimiter + tag
		}
		lines = append(lines, newLine)
	}

	err = k.writeLines(lines)
	if err != nil {
		return fmt.Errorf("error writing store file: %w", err)
	}

	return nil
}

func printUsage() {
	fmt.Print(`slpd - encrypted key-value store using your SSH key (v` + version + `)

Usage:
  slpd <command> [options] [arguments]
  slpd KEY=VALUE              shorthand for 'slpd set KEY=VALUE'

Commands:
  set <key> <value>           set a key-value pair (also: set KEY=VALUE)
  get <key>                   retrieve the value for a key
  del <key>                   delete a key
  list [<filter>]             list keys, optionally filtered by substring
  dump                        print all key-value pairs (shell-safe quoting)
  version                     print version
  help                        show this help

Options:
  -t <tag>                    filter by or assign a tag
  -k <path>                   path to SSH private key (default: ~/.ssh/id_rsa)
  -s <path>                   path to store file (default: ~/.config/slippard/store.dat)

Environment variables:
  SLP_KEY_PATH                override SSH key path (same as -k)
  SLP_STORE_FILE              override store file path (same as -s)

CLI flags (-k, -s) take precedence over environment variables.

Examples:
  slpd set API_KEY sk-1234
  slpd get API_KEY
  slpd set -t prod DB_HOST=db.example.com
  slpd list -t prod
  slpd dump -t prod
  slpd list | fzf | xargs slpd get
  export $(slpd dump)
`)
}

func main() {
	// Set keystore key and file path to defaults.
	store := KeyStore{
		keyPath:   os.Getenv("HOME") + "/.ssh/id_rsa",
		storeFile: os.Getenv("HOME") + "/.config/slippard/store.dat",
	}
	// if env var SLP_KEY_PATH is set, use it
	if os.Getenv("SLP_KEY_PATH") != "" {
		store.keyPath = os.Getenv("SLP_KEY_PATH")
	}
	// if env var SLP_STORE_FILE is set, use it
	if os.Getenv("SLP_STORE_FILE") != "" {
		store.storeFile = os.Getenv("SLP_STORE_FILE")
	}

	tag := ""

	// Parse global flags before command dispatch
	args := os.Args[1:]
	var filtered []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: -t requires an argument")
				os.Exit(1)
			}
			tag = args[i+1]
			i++
		case "-k":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: -k requires an argument")
				os.Exit(1)
			}
			store.keyPath = args[i+1]
			i++
		case "-s":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Error: -s requires an argument")
				os.Exit(1)
			}
			store.storeFile = args[i+1]
			i++
		default:
			filtered = append(filtered, args[i])
		}
	}

	if len(filtered) == 0 {
		printUsage()
		return
	}

	command := filtered[0]

	if command == "help" || command == "-h" || command == "--help" {
		printUsage()
		return
	}

	if command == "version" || command == "--version" || command == "-v" {
		fmt.Println("slpd " + version)
		return
	}

	// if store file does not exist, create it
	if _, err := os.Stat(store.storeFile); os.IsNotExist(err) {
		err := store.create()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating store file: %v\n", err)
			os.Exit(1)
		}
	}

	switch command {
	case "set":
		if len(filtered) < 2 || len(filtered) > 3 {
			fmt.Fprintln(os.Stderr, "Usage: slpd set [-t <tag>] <key> <value> or slpd set [-t <tag>] <key>=<value>")
			os.Exit(1)
		}
		key, value := "", ""
		if len(filtered) == 3 {
			key, value = filtered[1], filtered[2]
		} else {
			parts := strings.SplitN(filtered[1], "=", 2)
			if len(parts) != 2 {
				fmt.Fprintln(os.Stderr, "Invalid format. Use KEY=VALUE or KEY VALUE")
				os.Exit(1)
			}
			key, value = parts[0], parts[1]
		}
		err := store.setKeyValue(key, value, tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error setting key: %v\n", err)
			os.Exit(1)
		}
	case "get":
		if len(filtered) != 2 {
			fmt.Fprintln(os.Stderr, "Usage: slpd get [-t <tag>] <key>")
			os.Exit(1)
		}
		key := filtered[1]
		val, err := store.getKeyValue(key, tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(val)
	case "del":
		if len(filtered) != 2 {
			fmt.Fprintln(os.Stderr, "Usage: slpd del <key>")
			os.Exit(1)
		}
		key := filtered[1]
		err := store.delKeyValue(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting key: %v\n", err)
			os.Exit(1)
		}
	case "list":
		filter := ""
		if len(filtered) == 2 {
			filter = filtered[1]
		} else if len(filtered) > 2 {
			fmt.Fprintln(os.Stderr, "Usage: slpd list [-t <tag>] [<filter>]")
			os.Exit(1)
		}
		result, err := store.listKeys(filter, tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing keys: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(result)
	case "dump":
		dump, err := store.dumpStore(tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error dumping store: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(dump)
	default:
		if strings.Contains(command, "=") {
			parts := strings.SplitN(command, "=", 2)
			err := store.setKeyValue(parts[0], parts[1], tag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error setting key: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Unknown command: %s\nRun 'slpd help' for usage.\n", command)
			os.Exit(1)
		}
	}
}
