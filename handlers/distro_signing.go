package handlers

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"kerio-mirror-go/config"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

const defaultDistroMaxUploadBytes int64 = 2 * 1024 * 1024 * 1024

var (
	distroFilenamePattern = regexp.MustCompile(`^kerio-control-upgrade-(\d+\.\d+\.\d+-\d+)[A-Za-z0-9_.-]*\.img$`)
	distroUnsafeChars     = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)
	distroPublishMu       sync.Mutex

	errInvalidDistroFilename = errors.New("invalid distro filename")
	errDistroTooLarge        = errors.New("distro upload exceeds configured limit")
)

type distroUploadResult struct {
	File      string `json:"file"`
	Signature string `json:"signature"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}

// RegisterDistroAdminRoutes registers authenticated distribution-management endpoints.
func RegisterDistroAdminRoutes(e *echo.Echo, cfg *config.Config, logger *logrus.Logger) {
	protected := requireAdminAuth(cfg)
	e.POST(apiBase+"/distro/upload", protected(distroUploadHandler(logger)))
	e.GET(apiBase+"/distro/list", protected(distroListHandler()))
}

func distroUploadHandler(logger *logrus.Logger) echo.HandlerFunc {
	return func(c echo.Context) error {
		header, err := c.FormFile("distro_file")
		if err != nil {
			header, err = c.FormFile("file")
		}
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "multipart field distro_file is required"})
		}

		source, err := header.Open()
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot open uploaded file"})
		}
		defer source.Close()

		result, err := storeAndSignDistro(source, header.Filename, distroSigningKeyPath(), distroMaxUploadBytes())
		if err != nil {
			switch {
			case errors.Is(err, errInvalidDistroFilename):
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			case errors.Is(err, errDistroTooLarge):
				return c.JSON(http.StatusRequestEntityTooLarge, map[string]string{"error": err.Error()})
			default:
				logger.Errorf("Distro upload/sign failed for %q: %v", header.Filename, err)
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to store and sign distro"})
			}
		}

		logger.Infof("Distro uploaded and signed: %s sha256=%s size=%d", result.File, result.SHA256, result.Size)
		return c.JSON(http.StatusOK, result)
	}
}

func distroListHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		files, err := listSignedDistros(filepath.Join("mirror", "distros"))
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list distros"})
		}
		return c.JSON(http.StatusOK, map[string]any{"distros": files})
	}
}

func distroSigningKeyPath() string {
	if value := strings.TrimSpace(os.Getenv("KERIO_DISTRO_SIGNING_KEY")); value != "" {
		return value
	}
	return filepath.Join("certs", "key.pem")
}

func distroMaxUploadBytes() int64 {
	value := strings.TrimSpace(os.Getenv("KERIO_DISTRO_MAX_UPLOAD_BYTES"))
	if value == "" {
		return defaultDistroMaxUploadBytes
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return defaultDistroMaxUploadBytes
	}
	return parsed
}

func storeAndSignDistro(source io.Reader, originalName, privateKeyPath string, maxBytes int64) (distroUploadResult, error) {
	return storeAndSignDistroAt(source, originalName, privateKeyPath, maxBytes, filepath.Join("mirror", "distros"))
}

func storeAndSignDistroAt(source io.Reader, originalName, privateKeyPath string, maxBytes int64, dir string) (distroUploadResult, error) {
	var result distroUploadResult
	filename := secureDistroFilename(originalName)
	if !distroFilenamePattern.MatchString(filename) {
		return result, fmt.Errorf("%w: expected kerio-control-upgrade-{version}.img", errInvalidDistroFilename)
	}
	if maxBytes <= 0 {
		maxBytes = defaultDistroMaxUploadBytes
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return result, fmt.Errorf("create distro directory: %w", err)
	}

	imageTemp, err := os.CreateTemp(dir, ".distro-*.img.tmp")
	if err != nil {
		return result, fmt.Errorf("create image temp file: %w", err)
	}
	imageTempPath := imageTemp.Name()
	defer os.Remove(imageTempPath)

	hasher := sha256.New()
	limited := &io.LimitedReader{R: source, N: maxBytes + 1}
	size, copyErr := io.Copy(io.MultiWriter(imageTemp, hasher), limited)
	if copyErr != nil {
		_ = imageTemp.Close()
		return result, fmt.Errorf("write uploaded image: %w", copyErr)
	}
	if size > maxBytes {
		_ = imageTemp.Close()
		return result, errDistroTooLarge
	}
	if err := imageTemp.Sync(); err != nil {
		_ = imageTemp.Close()
		return result, fmt.Errorf("sync uploaded image: %w", err)
	}
	if err := imageTemp.Close(); err != nil {
		return result, fmt.Errorf("close uploaded image: %w", err)
	}

	digest := hasher.Sum(nil)
	privateKey, err := loadRSAPrivateKey(privateKeyPath)
	if err != nil {
		return result, fmt.Errorf("load distro signing key: %w", err)
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
	if err != nil {
		return result, fmt.Errorf("sign distro digest: %w", err)
	}

	signatureTemp, err := os.CreateTemp(dir, ".distro-*.sig.tmp")
	if err != nil {
		return result, fmt.Errorf("create signature temp file: %w", err)
	}
	signatureTempPath := signatureTemp.Name()
	defer os.Remove(signatureTempPath)
	if _, err := signatureTemp.Write(signature); err != nil {
		_ = signatureTemp.Close()
		return result, fmt.Errorf("write signature: %w", err)
	}
	if err := signatureTemp.Sync(); err != nil {
		_ = signatureTemp.Close()
		return result, fmt.Errorf("sync signature: %w", err)
	}
	if err := signatureTemp.Close(); err != nil {
		return result, fmt.Errorf("close signature: %w", err)
	}

	imagePath := filepath.Join(dir, filename)
	signaturePath := imagePath + ".sig"
	distroPublishMu.Lock()
	err = publishDistroPair(imageTempPath, signatureTempPath, imagePath, signaturePath)
	distroPublishMu.Unlock()
	if err != nil {
		return result, err
	}

	result = distroUploadResult{
		File:      filename,
		Signature: filepath.Base(signaturePath),
		SHA256:    hex.EncodeToString(digest),
		Size:      size,
	}
	return result, nil
}

func secureDistroFilename(filename string) string {
	base := filepath.Base(strings.TrimSpace(filename))
	return distroUnsafeChars.ReplaceAllString(base, "_")
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("PEM block not found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#1/PKCS#8 RSA key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}

func publishDistroPair(imageTemp, signatureTemp, imagePath, signaturePath string) error {
	suffix := ".bak-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	imageBackup := imagePath + suffix
	signatureBackup := signaturePath + suffix

	imageBackedUp, err := backupExistingFile(imagePath, imageBackup)
	if err != nil {
		return fmt.Errorf("backup existing distro: %w", err)
	}
	signatureBackedUp, err := backupExistingFile(signaturePath, signatureBackup)
	if err != nil {
		restoreBackup(imageBackup, imagePath, imageBackedUp)
		return fmt.Errorf("backup existing signature: %w", err)
	}

	rollback := func() {
		_ = os.Remove(imagePath)
		_ = os.Remove(signaturePath)
		restoreBackup(imageBackup, imagePath, imageBackedUp)
		restoreBackup(signatureBackup, signaturePath, signatureBackedUp)
	}

	if err := os.Rename(signatureTemp, signaturePath); err != nil {
		rollback()
		return fmt.Errorf("publish distro signature: %w", err)
	}
	if err := os.Rename(imageTemp, imagePath); err != nil {
		rollback()
		return fmt.Errorf("publish distro image: %w", err)
	}

	if imageBackedUp {
		_ = os.Remove(imageBackup)
	}
	if signatureBackedUp {
		_ = os.Remove(signatureBackup)
	}
	return nil
}

func backupExistingFile(path, backup string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	if err := os.Rename(path, backup); err != nil {
		return false, err
	}
	return true, nil
}

func restoreBackup(backup, destination string, exists bool) {
	if !exists {
		return
	}
	_ = os.Remove(destination)
	_ = os.Rename(backup, destination)
}

func listSignedDistros(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}

	available := make(map[string]bool)
	for _, entry := range entries {
		if !entry.Type().IsRegular() && entry.Type() != 0 {
			continue
		}
		available[entry.Name()] = true
	}

	result := make([]string, 0)
	for name := range available {
		if distroFilenamePattern.MatchString(name) && available[name+".sig"] {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result, nil
}
