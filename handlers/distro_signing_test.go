package handlers

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreAndSignDistroPreservesImageAndCreatesValidSignature(t *testing.T) {
	dir := t.TempDir()
	key, keyPath := writeTestRSAKey(t, dir)
	payload := []byte("unchanged Kerio distro payload")
	filename := "kerio-control-upgrade-9.5.0-9017.img"

	result, err := storeAndSignDistroAt(bytes.NewReader(payload), filename, keyPath, int64(len(payload)+1), dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.File != filename || result.Signature != filename+".sig" || result.Size != int64(len(payload)) {
		t.Fatalf("unexpected result: %+v", result)
	}

	stored, err := os.ReadFile(filepath.Join(dir, filename))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatal("stored image differs from uploaded image")
	}

	signature, err := os.ReadFile(filepath.Join(dir, filename+".sig"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	files, err := listSignedDistros(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != filename {
		t.Fatalf("unexpected distro list: %#v", files)
	}
}

func TestStoreAndSignDistroRejectsInvalidFilename(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writeTestRSAKey(t, dir)
	_, err := storeAndSignDistroAt(bytes.NewReader([]byte("payload")), "firmware.img", keyPath, 1024, dir)
	if !errors.Is(err, errInvalidDistroFilename) {
		t.Fatalf("expected invalid filename error, got %v", err)
	}
}

func TestStoreAndSignDistroRejectsOversizedUpload(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writeTestRSAKey(t, dir)
	_, err := storeAndSignDistroAt(
		bytes.NewReader([]byte("payload larger than limit")),
		"kerio-control-upgrade-9.5.0-9017.img",
		keyPath,
		4,
		dir,
	)
	if !errors.Is(err, errDistroTooLarge) {
		t.Fatalf("expected upload limit error, got %v", err)
	}
}

func TestListSignedDistrosRequiresSignaturePair(t *testing.T) {
	dir := t.TempDir()
	unsigned := "kerio-control-upgrade-9.4.0-1000.img"
	signed := "kerio-control-upgrade-9.5.0-9017.img"
	if err := os.WriteFile(filepath.Join(dir, unsigned), []byte("unsigned"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, signed), []byte("signed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, signed+".sig"), []byte("signature"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := listSignedDistros(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != signed {
		t.Fatalf("unexpected distro list: %#v", files)
	}
}

func writeTestRSAKey(t *testing.T, dir string) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "key.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return key, path
}
