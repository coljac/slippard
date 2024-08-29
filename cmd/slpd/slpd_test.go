package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func setupTestEnv() {
	os.Setenv("HOME", "/tmp")
	os.Setenv("SLP_KEY_PATH", "/tmp/.ssh/id_rsa")
	os.Setenv("SLP_STORE_FILE", "/tmp/.config/slippard/store.dat")
	os.MkdirAll("/tmp/.config/slippard", os.ModePerm)

	// Generate a new RSA key in PEM format for testing
	os.MkdirAll("/tmp/.ssh", os.ModePerm)
	os.Remove("/tmp/.ssh/id_rsa")
	os.Remove("/tmp/.ssh/id_rsa.pub")
	cmd := exec.Command("ssh-keygen", "-t", "rsa", "-m", "PEM", "-f", "/tmp/.ssh/id_rsa", "-N", "")
	err := cmd.Run()
	if err != nil {
		panic(err)
	}
}

func teardownTestEnv() {
	os.Unsetenv("HOME")
	os.Unsetenv("SLP_KEY_PATH")
	os.Unsetenv("SLP_STORE_FILE")
	os.RemoveAll("/tmp/.config/slippard")
	os.RemoveAll("/tmp/.ssh")
}

func TestKeyStore_SetGetKeyValue(t *testing.T) {
	setupTestEnv()
	defer teardownTestEnv()

	store := KeyStore{
		keyPath:   os.Getenv("SLP_KEY_PATH"),
		storeFile: os.Getenv("SLP_STORE_FILE"),
	}

	err := store.create()
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	longKey := strings.Repeat("k", 1000)
	longValue := strings.Repeat("v", 1000)

	err = store.setKeyValue(longKey, longValue, "")
	if err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	val, err := store.getKeyValue(longKey, "")
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	if val != longValue {
		t.Errorf("Expected value %s, got %s", longValue, val)
	}
}

func TestKeyStore_TagFiltering(t *testing.T) {
	setupTestEnv()
	defer teardownTestEnv()

	store := KeyStore{
		keyPath:   os.Getenv("SLP_KEY_PATH"),
		storeFile: os.Getenv("SLP_STORE_FILE"),
	}

	err := store.create()
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	err = store.setKeyValue("key1", "value1", "tag1")
	if err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	err = store.setKeyValue("key2", "value2", "tag2")
	if err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	val, err := store.getKeyValue("key1", "tag1")
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	if val != "value1" {
		t.Errorf("Expected value1, got %s", val)
	}

	val, err = store.getKeyValue("key2", "tag1")
	if err == nil {
		t.Errorf("Expected error, got value %s", val)
	}
}

func TestKeyStore_EnvironmentVariables(t *testing.T) {
	setupTestEnv()
	defer teardownTestEnv()

	store := KeyStore{
		keyPath:   os.Getenv("SLP_KEY_PATH"),
		storeFile: os.Getenv("SLP_STORE_FILE"),
	}

	err := store.create()
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	err = store.setKeyValue("envKey", "envValue", "")
	if err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	val, err := store.getKeyValue("envKey", "")
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	if val != "envValue" {
		t.Errorf("Expected envValue, got %s", val)
	}
}

func TestKeyStore_HandleLargeNumberOfKeys(t *testing.T) {
	setupTestEnv()
	defer teardownTestEnv()

	store := KeyStore{
		keyPath:   os.Getenv("SLP_KEY_PATH"),
		storeFile: os.Getenv("SLP_STORE_FILE"),
	}

	err := store.create()
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	for i := 0; i < 1000; i++ {
		key := "key" + strconv.Itoa(i)
		value := "value" + strconv.Itoa(i)
		err = store.setKeyValue(key, value, "")
		if err != nil {
			t.Fatalf("Failed to set key %d: %v", i, err)
		}
	}

	for i := 0; i < 1000; i++ {
		key := "key" + strconv.Itoa(i)
		expectedValue := "value" + strconv.Itoa(i)
		val, err := store.getKeyValue(key, "")
		if err != nil {
			t.Fatalf("Failed to get key %d: %v", i, err)
		}

		if val != expectedValue {
			t.Errorf("Expected %s, got %s", expectedValue, val)
		}
	}
}
