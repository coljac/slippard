// main.go
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	crypt "github.com/coljac/slippard/internal/encryption"
)

type KeyStore struct {
	keyPath string
	keyFile string
}

func (k KeyStore) writeLines(lines []string) error {
	// TODO: Create a backup of the file before writing in case of error
	filename, keyPath := k.keyFile, k.keyPath
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// writer := bufio.NewWriter(file)
	var writer strings.Builder

	for _, line := range lines {
		writer.WriteString(line + "\n")
	}
	cipherText, err := crypt.EncryptWithSSHKey(writer.String(), keyPath)
	if err != nil {
		return err
	}
	_, err = file.Write([]byte(cipherText))
	if err != nil {
		return err
	}
	return nil
}

func (k KeyStore) create() error {
	filename, _ := k.keyFile, k.keyPath
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return nil
}

func (k KeyStore) readLines() ([]string, error) {
	filename, keyPath := k.keyFile, k.keyPath
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string

	cipherText, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(cipherText) == 0 {
		return lines, nil
	}
	plainText, err := crypt.DecryptWithSSHKey(cipherText, keyPath)
	if err != nil {
		return nil, err
	}

	// iterate over lines in plainText
	scanner := bufio.NewScanner(strings.NewReader(plainText))
	// scanner := bufio.NewScanner(plainText)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func (k KeyStore) listKeys(filter string) (string, error) {
	lines, err := k.readLines()
	if err != nil {
		return "", fmt.Errorf("error reading store file: %w", err)
	}
	var builder strings.Builder
	for _, line := range lines {
		if filter == "" || strings.Contains(line, filter) {
			key := strings.SplitN(line, "=", 2)[0]
			builder.WriteString(key + "\n")
		}
	}

	return builder.String(), nil
}

func (k KeyStore) delKeyValue(key string) error {
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

func (k KeyStore) dumpStore() (string, error) {
	lines, err := k.readLines()
	if err != nil {
		return "", fmt.Errorf("error reading store file: %w", err)
	}

	return strings.Join(lines, "\n"), nil
}

func (k KeyStore) getKeyValue(key string) (string, error) {
	lines, err := k.readLines()
	if err != nil {
		return "", fmt.Errorf("error reading store file: %w", err)
	}

	for _, line := range lines {
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimPrefix(line, key+"="), nil
		}
	}

	return "", fmt.Errorf("key not found")
}

func (k KeyStore) setKeyValue(key, value string) error {
	lines, err := k.readLines()
	if err != nil {
		return fmt.Errorf("error reading store file: %w", err)
	}

	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, key+"=") {
			lines[i] = key + "=" + value
			found = true
			break
		}
	}

	if !found {
		lines = append(lines, key+"="+value)
	}

	err = k.writeLines(lines)
	if err != nil {
		return fmt.Errorf("error writing store file: %w", err)
	}

	return nil
}

func main() {
	store := KeyStore{
		keyPath: os.Getenv("HOME") + "/.ssh/id_rsa",
		keyFile: os.Getenv("HOME") + "/.config/slippard/store.dat",
	}
	// if keyFile does not exist, create it
	if _, err := os.Stat(store.keyFile); os.IsNotExist(err) {
		err := store.create()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating store file: %v", err)
			os.Exit(1)
		}
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage: slpd <command> [arguments]")
		return
	}

	command := os.Args[1]

	switch command {
	case "set":
		if len(os.Args) < 3 || len(os.Args) > 4 {
			fmt.Println("Usage: slpd set <key> <value> or slpd set <key>=<value>")
			os.Exit(1)
		}
		key, value := "", ""
		if len(os.Args) == 4 {
			key, value = os.Args[2], os.Args[3]
		} else {
			// split os.Args[2] by "="
			parts := strings.SplitN(os.Args[2], "=", 2)
			if len(parts) != 2 {
				fmt.Println("Invalid format. Use KEY=VALUE")
				os.Exit(1)
				// return
			}
			key, value = parts[0], parts[1]
		}
		store.setKeyValue(key, value)
	case "get":
		if len(os.Args) != 3 {
			fmt.Println("Usage: slpd get <key>")
			os.Exit(1)
			// return
		}
		key := os.Args[2]
		val, err := store.getKeyValue(key)
		if err == nil {
			fmt.Println(val)
		} else {
			fmt.Fprintf(os.Stderr, "Error getting key: %v", err)
		}
	case "del":
		if len(os.Args) != 3 {
			fmt.Println("Usage: slpd del <key>")
			return
		}
		key := os.Args[2]
		store.delKeyValue(key)
	case "list":
		if len(os.Args) == 3 {
			filter := os.Args[2]
			keys, err := store.listKeys(filter)
			if err == nil {
				fmt.Print(keys)
			} else {
				fmt.Fprintf(os.Stderr, "Error listing keys: %v", err)
			}
		} else if len(os.Args) == 2 {
			result, err := store.listKeys("")
			if err == nil {
				fmt.Print(result)
			} else {
				fmt.Fprintf(os.Stderr, "Error listing keys: %v", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Usage: slpd list [<string>]")
		}
	case "dump":
		dump, err := store.dumpStore()
		if err == nil {
			fmt.Println(dump)
		} else {
			fmt.Fprintf(os.Stderr, "Error dumping store: %v", err)
			os.Exit(1)
		}
	default:
		if strings.Contains(command, "=") {
			parts := strings.SplitN(command, "=", 2)
			if len(parts) != 2 {
				fmt.Fprintf(os.Stderr, "Invalid format. Use KEY=VALUE")
				return
			}
			store.setKeyValue(parts[0], parts[1])
		} else {
			fmt.Fprintf(os.Stderr, "Unknown command")
		}
	}
}
