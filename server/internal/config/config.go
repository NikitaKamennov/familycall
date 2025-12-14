package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	HTTPPort     string
	HTTPSPort    string
	Domain       string
	TURNPort     int
	TURNRealm    string
	DatabasePath string
	JWTSecret    string
	VAPIDKeys    *VAPIDKeys
}

type VAPIDKeys struct {
	PublicKey  string
	PrivateKey string
	Subject    string
}

func Load() *Config {
	cfg := &Config{
		// По умолчанию работаем ТОЛЬКО по HTTP за Nginx
		HTTPPort:     getEnv("HTTP_PORT", "5080"),
		HTTPSPort:    getEnv("HTTPS_PORT", "0"), // TLS отключён
		TURNPort:     getEnvInt("TURN_PORT", 3478),
		TURNRealm:    getEnv("TURN_REALM", "familycall"),
		DatabasePath: getEnv("DATABASE_PATH", "familycall.db"),
		JWTSecret:    loadOrGenerateJWTSecret(),
	}

	// Загружаем домен ТОЛЬКО неинтерактивно (ENV или файл). Без запросов в консоль.
	cfg.Domain = loadDomainNonInteractive()

	// Генерируем или загружаем VAPID ключи
	vapidKeys := loadVAPIDKeys()
	cfg.VAPIDKeys = vapidKeys

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func generateRandomSecret() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func loadOrGenerateJWTSecret() string {
	// 1) ENV приоритетнее всего
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		return secret
	}

	// 2) Файл на диске (рядом с бинарём, в подкаталоге keys)
	keysDir := getKeysDirectory()
	secretFile := filepath.Join(keysDir, "jwt-secret.key")
	if secretData, err := os.ReadFile(secretFile); err == nil {
		secret := strings.TrimSpace(string(secretData))
		if secret != "" {
			fmt.Printf("JWT secret loaded from: %s\n", secretFile)
			return secret
		}
	}

	// 3) Генерация нового секрета и сохранение
	secret := generateRandomSecret()
	if err := os.MkdirAll(keysDir, 0700); err == nil {
		if err := os.WriteFile(secretFile, []byte(secret), 0600); err == nil {
			fmt.Printf("JWT secret saved to: %s\n", secretFile)
		} else {
			fmt.Printf("Warning: Failed to save JWT secret to disk: %v\n", err)
			fmt.Println("Secret will be regenerated on next restart unless set via JWT_SECRET environment variable")
		}
	}
	return secret
}

func loadVAPIDKeys() *VAPIDKeys {
	// 1) ENV
	publicKey := os.Getenv("VAPID_PUBLIC_KEY")
	privateKey := os.Getenv("VAPID_PRIVATE_KEY")
	subject := os.Getenv("VAPID_SUBJECT")
	if publicKey != "" && privateKey != "" {
		return &VAPIDKeys{
			PublicKey:  publicKey,
			PrivateKey: privateKey,
			Subject:    getEnv("VAPID_SUBJECT", "mailto:admin@familycall.app"),
		}
	}

	// 2) Файлы на диске
	keysDir := getKeysDirectory()
	publicKeyFile := filepath.Join(keysDir, "vapid-public.key")
	privateKeyFile := filepath.Join(keysDir, "vapid-private.key")
	subjectFile := filepath.Join(keysDir, "vapid-subject.key")

	if publicKeyData, err := os.ReadFile(publicKeyFile); err == nil {
		if privateKeyData, err := os.ReadFile(privateKeyFile); err == nil {
			publicKey = string(publicKeyData)
			privateKey = string(privateKeyData)

			// Проверяем формат приватного ключа
			decodedPrivate, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(privateKey))
			if err == nil {
				if len(decodedPrivate) > 50 {
					// Старый PKCS#8 — удаляем и регенерируем
					fmt.Printf("WARNING: VAPID private key is in old PKCS#8 format (%d bytes). Deleting old keys to regenerate...\n", len(decodedPrivate))
					_ = os.Remove(publicKeyFile)
					_ = os.Remove(privateKeyFile)
					_ = os.Remove(subjectFile)
					// перейдём к генерации ниже
				} else if len(decodedPrivate) == 32 {
					// Валидный raw формат
					if subjectData, err := os.ReadFile(subjectFile); err == nil {
						subject = string(subjectData)
					} else {
						subject = getEnv("VAPID_SUBJECT", "mailto:admin@familycall.app")
					}
					return &VAPIDKeys{
						PublicKey:  publicKey,
						PrivateKey: privateKey,
						Subject:    subject,
					}
				} else {
					fmt.Printf("WARNING: VAPID private key has unexpected length (%d bytes). Deleting to regenerate...\n", len(decodedPrivate))
					_ = os.Remove(publicKeyFile)
					_ = os.Remove(privateKeyFile)
					_ = os.Remove(subjectFile)
					// перейдём к генерации ниже
				}
			} else {
				// Не декодируется — регенерируем
				fmt.Printf("WARNING: Cannot decode VAPID private key. Regenerating...\n")
				_ = os.Remove(publicKeyFile)
				_ = os.Remove(privateKeyFile)
				_ = os.Remove(subjectFile)
				// перейдём к генерации ниже
			}
		}
	}

	// 3) Генерация новых VAPID ключей
	privateKeyECDSA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("Failed to generate VAPID keys: " + err.Error())
	}

	// Публичный ключ (нежатая точка: 0x04 + X(32) + Y(32))
	publicKeyBytes := make([]byte, 65)
	publicKeyBytes[0] = 0x04
	privateKeyECDSA.PublicKey.X.FillBytes(publicKeyBytes[1:33])
	privateKeyECDSA.PublicKey.Y.FillBytes(publicKeyBytes[33:65])
	uncompressedPublicKey := base64.RawURLEncoding.EncodeToString(publicKeyBytes)

	// Приватный ключ (сырые 32 байта)
	privateKeyBytes := make([]byte, 32)
	privateKeyECDSA.D.FillBytes(privateKeyBytes)
	privateKeyBase64 := base64.RawURLEncoding.EncodeToString(privateKeyBytes)

	subject = getEnv("VAPID_SUBJECT", "mailto:admin@familycall.app")

	// Сохраняем
	if err := saveVAPIDKeys(keysDir, uncompressedPublicKey, privateKeyBase64, subject); err != nil {
		fmt.Printf("Warning: Failed to save VAPID keys to disk: %v\n", err)
		fmt.Println("Keys will be regenerated on next restart unless set via environment variables")
	}

	return &VAPIDKeys{
		PublicKey:  uncompressedPublicKey,
		PrivateKey: privateKeyBase64,
		Subject:    subject,
	}
}

func getKeysDirectory() string {
	// Каталог рядом с бинарём
	execPath, err := os.Executable()
	if err != nil {
		return "keys"
	}
	execDir := filepath.Dir(execPath)
	return filepath.Join(execDir, "keys")
}

func saveVAPIDKeys(keysDir, publicKey, privateKey, subject string) error {
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	publicKeyFile := filepath.Join(keysDir, "vapid-public.key")
	if err := os.WriteFile(publicKeyFile, []byte(publicKey), 0600); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	privateKeyFile := filepath.Join(keysDir, "vapid-private.key")
	if err := os.WriteFile(privateKeyFile, []byte(privateKey), 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	subjectFile := filepath.Join(keysDir, "vapid-subject.key")
	if err := os.WriteFile(subjectFile, []byte(subject), 0600); err != nil {
		return fmt.Errorf("failed to save subject: %w", err)
	}

	fmt.Printf("VAPID keys saved to: %s\n", keysDir)
	return nil
}

func getCertsDirectory() string {
	// Каталог рядом с бинарём
	execPath, err := os.Executable()
	if err != nil {
		return "certs"
	}
	execDir := filepath.Dir(execPath)
	return filepath.Join(execDir, "certs")
}

// НЕИНТЕРАКТИВНАЯ загрузка домена: только ENV или файл. Без запросов в консоль.
func loadDomainNonInteractive() string {
	// 1) ENV
	if domain := os.Getenv("DOMAIN"); domain != "" {
		return strings.TrimSpace(domain)
	}

	// 2) Файл рядом с бинарём
	certsDir := getCertsDirectory()
	domainFile := filepath.Join(certsDir, "domain.txt")
	if domainData, err := os.ReadFile(domainFile); err == nil {
		domain := strings.TrimSpace(string(domainData))
		if domain != "" {
			return domain
		}
	}

	// 3) Ничего не нашли — возвращаем пустую строку (main прошьёт нужное значение)
	return ""
}