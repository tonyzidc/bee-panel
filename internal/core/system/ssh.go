package system

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

type SSHCredentials struct {
	PrivateKeyOpenSSH string
	PublicKeyOpenSSH  string
	Password          string
}

// GenerateRandomPassword generates a secure random string of given length
func GenerateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	return string(bytes), nil
}

// GenerateEd25519Keypair generates an Ed25519 private/public keypair in OpenSSH format
func GenerateEd25519Keypair(comment string) (*SSHCredentials, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	// OpenSSH private key format
	privKeyBlock, err := ssh.MarshalPrivateKey(privKey, comment)
	if err != nil {
		return nil, fmt.Errorf("marshal ed25519 private key: %w", err)
	}
	privKeyPEM := pem.EncodeToMemory(privKeyBlock)

	// OpenSSH public key format
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("create ssh public key: %w", err)
	}
	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)

	// Generate 24-char temporary password
	password, err := GenerateRandomPassword(24)
	if err != nil {
		return nil, fmt.Errorf("generate random password: %w", err)
	}

	return &SSHCredentials{
		PrivateKeyOpenSSH: string(privKeyPEM),
		PublicKeyOpenSSH:  string(pubKeyBytes),
		Password:          password,
	}, nil
}

// SetupUserSSHKeys writes the authorized_keys file and configures permissions
func SetupUserSSHKeys(homeDir string, uid, gid int, publicKey string) error {
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("mkdir .ssh: %w", err)
	}
	if err := os.Chown(sshDir, uid, gid); err != nil {
		return fmt.Errorf("chown .ssh: %w", err)
	}

	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	f, err := os.OpenFile(authKeysPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open authorized_keys: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(strings.TrimSpace(publicKey) + "\n"); err != nil {
		return fmt.Errorf("write authorized_keys: %w", err)
	}

	if err := os.Chmod(authKeysPath, 0600); err != nil {
		return fmt.Errorf("chmod authorized_keys: %w", err)
	}
	if err := os.Chown(authKeysPath, uid, gid); err != nil {
		return fmt.Errorf("chown authorized_keys: %w", err)
	}

	return nil
}

// ReplaceUserSSHKey replaces the authorized_keys file with a single new public key
func ReplaceUserSSHKey(homeDir string, uid, gid int, newPublicKey string) error {
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("mkdir .ssh: %w", err)
	}
	_ = os.Chown(sshDir, uid, gid)

	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	content := strings.TrimSpace(newPublicKey) + "\n"
	if err := os.WriteFile(authKeysPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("write authorized_keys: %w", err)
	}

	_ = os.Chmod(authKeysPath, 0600)
	_ = os.Chown(authKeysPath, uid, gid)
	return nil
}
