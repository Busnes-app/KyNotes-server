package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/keyfile"
	"github.com/Busnes-app/ky-primitives/offsite"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    Server    `yaml:"server"`
	DataDir   string    `yaml:"data_dir"`
	Secrets   Secrets   `yaml:"secrets"`
	Limits    Limits    `yaml:"limits"`
	GC        GC        `yaml:"gc"`
	RateLimit RateLimit `yaml:"ratelimit"`
	Log       Log       `yaml:"log"`
	Backup    Backup    `yaml:"backup"`
}
type Server struct {
	Bind               string   `yaml:"bind"`
	BehindProxy        bool     `yaml:"behind_proxy"`
	TrustedProxies     []string `yaml:"trusted_proxies"`
	ReadHeaderTimeout  string   `yaml:"read_header_timeout"`
	ReadTimeout        string   `yaml:"read_timeout"`
	WriteTimeout       string   `yaml:"write_timeout"`
	IdleTimeout        string   `yaml:"idle_timeout"`
	ShutdownGrace      string   `yaml:"shutdown_grace"`
	MaxRequestBytes    int64    `yaml:"max_request_bytes"`
	DevInsecureCookies bool     `yaml:"dev_insecure_cookies"`
}
type Secrets struct {
	PairingSecret string `yaml:"pairing_secret"`
	ServerSaltKey string `yaml:"server_salt_key"`
}
type Limits struct {
	AttachmentMaxBytes int64  `yaml:"attachment_max_bytes"`
	ChunkBytes         int64  `yaml:"chunk_bytes"`
	ObjectMaxBytes     int64  `yaml:"object_max_bytes"`
	UploadSessionTTL   string `yaml:"upload_session_ttl"`
	UserQuotaBytes     int64  `yaml:"user_quota_bytes"`
	TeamQuotaBytes     int64  `yaml:"team_quota_bytes"`
}
type GC struct {
	Enabled   bool   `yaml:"enabled"`
	Retention string `yaml:"retention"`
	Interval  string `yaml:"interval"`
}
type RateLimit struct {
	LoginPerMinute  int `yaml:"login_per_minute"`
	PairingPerHour  int `yaml:"pairing_per_hour"`
	UploadPerMinute int `yaml:"upload_per_minute"`
}
type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Backup configures sealed-capsule backups. The schedule here is only the
// default; the admin setting in the UI overrides it.
type Backup struct {
	BlobTarget           BlobTarget `yaml:"blob_target"`
	Dir                  string     `yaml:"dir"`                    // KYNOTES_BACKUP_DIR: local directory for sealed copies
	Keep                 int        `yaml:"keep"`                   // KYNOTES_BACKUP_KEEP: newest N local copies kept
	DepositInterval      string     `yaml:"deposit_interval"`       // KYNOTES_BACKUP_DEPOSIT_INTERVAL: "0" disables, floor 15m
	AllowPrivateRecovery bool       `yaml:"allow_private_recovery"` // KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY: admit a LAN KyRecovery
}

// AppName is the service name sealed into every capsule and pinned by
// KyRecovery at pairing.
const AppName = "KyNotes"

// MinBackupDepositInterval is the shortest schedule accepted: every run
// snapshots the whole database.
const MinBackupDepositInterval = 15 * time.Minute

func Defaults() Config {
	return Config{Server: Server{Bind: "0.0.0.0:8080", BehindProxy: true, TrustedProxies: []string{"127.0.0.1/32"}, ReadHeaderTimeout: "10s", ReadTimeout: "60s", WriteTimeout: "120s", IdleTimeout: "120s", ShutdownGrace: "20s", MaxRequestBytes: 1048576}, DataDir: "/data", Limits: Limits{AttachmentMaxBytes: 26214400, ChunkBytes: 4194304, ObjectMaxBytes: 10485760, UploadSessionTTL: "15m", UserQuotaBytes: 1073741824, TeamQuotaBytes: 5368709120}, GC: GC{Enabled: true, Retention: "168h", Interval: "1h"}, RateLimit: RateLimit{LoginPerMinute: 10, PairingPerHour: 20, UploadPerMinute: 60}, Log: Log{Level: "info", Format: "json"}, Backup: Backup{Keep: 7, DepositInterval: "24h"}}
}

func Load(path string) (Config, error) { return load(path, false) }

// LoadBlobTargetProbe permits an absent SFTP pin only for the rejecting discovery
// handshake. offsite.Test never authenticates to an unpinned host.
func LoadBlobTargetProbe(path string) (Config, error) { return load(path, true) }

func load(path string, probe bool) (Config, error) {
	c := Defaults()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return c, err
		}
		if err == nil {
			if err = yaml.Unmarshal(b, &c); err != nil {
				return c, err
			}
		}
	}
	if err := applyEnv(&c); err != nil {
		return c, err
	}
	if err := loadSecrets(&c); err != nil {
		return c, err
	}
	if probe {
		validation := c
		validation.Backup.BlobTarget = BlobTarget{}
		if err := Validate(validation); err != nil {
			return c, err
		}
		if c.Backup.BlobTarget.URL != "" {
			if _, err := offsite.Parse(c.Backup.BlobTarget.Offsite()); err != nil {
				return c, errors.New("invalid blob probe target")
			}
		}
		return c, nil
	}
	return c, Validate(c)
}
func loadSecrets(c *Config) error {
	if c.DataDir == "" {
		return nil
	}
	if c.Secrets.PairingSecret != "" && c.Secrets.ServerSaltKey != "" {
		return nil
	}
	dir := filepath.Join(c.DataDir, "secrets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for name, dst := range map[string]*string{"pairing.key": &c.Secrets.PairingSecret, "serversalt.key": &c.Secrets.ServerSaltKey} {
		if *dst != "" {
			continue
		}
		// An existing file that does not decode to 32 bytes is an error, never
		// replaced and never silently an empty secret.
		raw, err := keyfile.LoadOrCreateEncoded(filepath.Join(dir, name), 32, keyfile.Base64)
		if err != nil {
			return fmt.Errorf("secrets/%s: %w", name, err)
		}
		*dst = string(raw)
	}
	return nil
}
func applyEnv(c *Config) error {
	applyBlobEnv(&c.Backup.BlobTarget)
	if v := os.Getenv("KYNOTES_PORT"); v != "" {
		c.Server.Bind = "0.0.0.0:" + v
	} else if v := os.Getenv("PORT"); v != "" {
		c.Server.Bind = "0.0.0.0:" + v
	}
	if v := os.Getenv("KYNOTES_SERVER_BIND"); v != "" {
		c.Server.Bind = v
	}
	if v := os.Getenv("KYNOTES_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("KYNOTES_SERVER_BEHIND_PROXY"); v != "" {
		c.Server.BehindProxy, _ = strconv.ParseBool(v)
	}
	if v := os.Getenv("TRUSTED_PROXY_CIDRS"); v != "" {
		c.Server.TrustedProxies = strings.Split(v, ",")
		c.Server.BehindProxy = true
	}
	if v := os.Getenv("KYNOTES_SERVER_TRUSTED_PROXIES"); v != "" {
		c.Server.TrustedProxies = strings.Split(v, ",")
	}
	if v := os.Getenv("KYNOTES_SERVER_DEV_INSECURE_COOKIES"); v != "" {
		c.Server.DevInsecureCookies, _ = strconv.ParseBool(v)
	}
	if v := os.Getenv("KYNOTES_SERVER_MAX_REQUEST_BYTES"); v != "" {
		if err := parseEnvInt64(v, &c.Server.MaxRequestBytes, "server.max_request_bytes"); err != nil {
			return err
		}
	}
	if v := os.Getenv("KYNOTES_SECRETS_PAIRING_SECRET"); v != "" {
		c.Secrets.PairingSecret = v
	}
	if v := os.Getenv("KYNOTES_SECRETS_SERVER_SALT_KEY"); v != "" {
		c.Secrets.ServerSaltKey = v
	}
	if v := os.Getenv("KYNOTES_LIMITS_ATTACHMENT_MAX_BYTES"); v != "" {
		if err := parseEnvInt64(v, &c.Limits.AttachmentMaxBytes, "limits.attachment_max_bytes"); err != nil {
			return err
		}
	}
	if v := os.Getenv("KYNOTES_LIMITS_CHUNK_BYTES"); v != "" {
		if err := parseEnvInt64(v, &c.Limits.ChunkBytes, "limits.chunk_bytes"); err != nil {
			return err
		}
	}
	if v := os.Getenv("KYNOTES_LIMITS_OBJECT_MAX_BYTES"); v != "" {
		if err := parseEnvInt64(v, &c.Limits.ObjectMaxBytes, "limits.object_max_bytes"); err != nil {
			return err
		}
	}
	if v := os.Getenv("KYNOTES_LIMITS_UPLOAD_SESSION_TTL"); v != "" {
		c.Limits.UploadSessionTTL = v
	}
	if v := os.Getenv("KYNOTES_LIMITS_USER_QUOTA_BYTES"); v != "" {
		if err := parseEnvInt64(v, &c.Limits.UserQuotaBytes, "limits.user_quota_bytes"); err != nil {
			return err
		}
	}
	if v := os.Getenv("KYNOTES_LIMITS_TEAM_QUOTA_BYTES"); v != "" {
		if err := parseEnvInt64(v, &c.Limits.TeamQuotaBytes, "limits.team_quota_bytes"); err != nil {
			return err
		}
	}
	if v := os.Getenv("KYNOTES_GC_ENABLED"); v != "" {
		c.GC.Enabled, _ = strconv.ParseBool(v)
	}
	if v := os.Getenv("KYNOTES_GC_RETENTION"); v != "" {
		c.GC.Retention = v
	}
	if v := os.Getenv("KYNOTES_GC_INTERVAL"); v != "" {
		c.GC.Interval = v
	}
	if v := os.Getenv("KYNOTES_RATELIMIT_LOGIN_PER_MINUTE"); v != "" {
		c.RateLimit.LoginPerMinute, _ = strconv.Atoi(v)
	}
	if v := os.Getenv("KYNOTES_RATELIMIT_PAIRING_PER_HOUR"); v != "" {
		c.RateLimit.PairingPerHour, _ = strconv.Atoi(v)
	}
	if v := os.Getenv("KYNOTES_RATELIMIT_UPLOAD_PER_MINUTE"); v != "" {
		c.RateLimit.UploadPerMinute, _ = strconv.Atoi(v)
	}
	if v := os.Getenv("KYNOTES_LOG_LEVEL"); v != "" {
		c.Log.Level = v
	}
	if v := os.Getenv("KYNOTES_LOG_FORMAT"); v != "" {
		c.Log.Format = v
	}
	if v := os.Getenv("KYNOTES_BACKUP_DIR"); v != "" {
		c.Backup.Dir = v
	}
	if v := os.Getenv("KYNOTES_BACKUP_KEEP"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return errors.New("KYNOTES_BACKUP_KEEP: want a positive integer")
		}
		c.Backup.Keep = n
	}
	if v := os.Getenv("KYNOTES_BACKUP_DEPOSIT_INTERVAL"); v != "" {
		c.Backup.DepositInterval = v
	}
	if v := os.Getenv("KYNOTES_BACKUP_ALLOW_PRIVATE_RECOVERY"); v != "" {
		c.Backup.AllowPrivateRecovery = v == "true" || v == "1"
	}
	return nil
}

func parseEnvInt64(value string, dst *int64, name string) error {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fmt.Errorf("%s: invalid: %w", name, err)
	}
	*dst = n
	return nil
}
func duration(name, value string) error {
	d, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if d <= 0 {
		return fmt.Errorf("%s: must be positive", name)
	}
	return nil
}
func Validate(c Config) error {
	if err := ValidateBlobTarget(c.Backup.BlobTarget); err != nil {
		return err
	}
	if c.DataDir == "" {
		return errors.New("data_dir: required")
	}
	st, err := os.Stat(c.DataDir)
	if err != nil {
		return fmt.Errorf("data_dir: %w", err)
	}
	if !st.IsDir() {
		return errors.New("data_dir: not a directory")
	}
	f, err := os.CreateTemp(c.DataDir, ".kynotes-write-")
	if err != nil {
		return fmt.Errorf("data_dir: not writable: %w", err)
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	if _, _, err = net.SplitHostPort(c.Server.Bind); err != nil {
		return fmt.Errorf("server.bind: invalid: %w", err)
	}
	if c.Server.DevInsecureCookies {
		host, _, _ := net.SplitHostPort(c.Server.Bind)
		if host != "127.0.0.1" && host != "::1" && host != "localhost" {
			return errors.New("server.dev_insecure_cookies: non-loopback bind")
		}
	}
	if c.Server.BehindProxy && len(c.Server.TrustedProxies) == 0 {
		return errors.New("server.trusted_proxies: required when behind_proxy")
	}
	if c.Limits.ChunkBytes < 65536 || c.Limits.ChunkBytes > c.Limits.AttachmentMaxBytes {
		return errors.New("limits.chunk_bytes: outside allowed range")
	}
	if c.Limits.AttachmentMaxBytes < 0 || c.Limits.ObjectMaxBytes < 0 || c.Limits.UserQuotaBytes < 0 || c.Limits.TeamQuotaBytes < 0 || c.Server.MaxRequestBytes < 0 {
		return errors.New("limits: byte sizes must not be negative")
	}
	if c.Limits.AttachmentMaxBytes < c.Limits.ChunkBytes {
		return errors.New("limits.attachment_max_bytes: smaller than chunk_bytes")
	}
	if c.GC.Enabled {
		d, e := time.ParseDuration(c.GC.Retention)
		if e != nil {
			return fmt.Errorf("gc.retention: %w", e)
		}
		if d < time.Hour {
			return errors.New("gc.retention: must be at least 1h")
		}
	}
	if c.Secrets.PairingSecret != "" && len(c.Secrets.PairingSecret) < 32 {
		return errors.New("secrets.pairing_secret: too short")
	}
	// Synthetic login salts are an HMAC under this key; the library refuses
	// anything under 32 bytes, so refuse it here rather than serve empty salts.
	if c.Secrets.ServerSaltKey != "" && len(c.Secrets.ServerSaltKey) < 32 {
		return errors.New("secrets.server_salt_key: too short")
	}
	if c.Backup.Keep < 1 {
		return errors.New("backup.keep: must be at least 1")
	}
	if d, err := time.ParseDuration(c.Backup.DepositInterval); err != nil || d < 0 || d > 366*24*time.Hour || (d != 0 && d < MinBackupDepositInterval) {
		return fmt.Errorf("backup.deposit_interval: 0 (off), or %s through 8784h", MinBackupDepositInterval)
	}
	for _, p := range [][2]string{{"server.read_header_timeout", c.Server.ReadHeaderTimeout}, {"server.read_timeout", c.Server.ReadTimeout}, {"server.write_timeout", c.Server.WriteTimeout}, {"server.idle_timeout", c.Server.IdleTimeout}, {"server.shutdown_grace", c.Server.ShutdownGrace}, {"limits.upload_session_ttl", c.Limits.UploadSessionTTL}, {"gc.interval", c.GC.Interval}} {
		if err := duration(p[0], p[1]); err != nil {
			return err
		}
	}
	if abs, _ := filepath.Abs(c.DataDir); strings.HasPrefix(abs, "/tmp/") && !c.Server.DevInsecureCookies {
		return errors.New("data_dir: must not be inside /tmp")
	}
	return nil
}
