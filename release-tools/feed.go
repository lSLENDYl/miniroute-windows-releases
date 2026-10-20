// Package releasefeed verifies public release metadata. It performs no network
// operations, installs nothing, and contains no publishing credentials.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxFeedBytes = 64 * 1024
const signingContext = "MiniRoute release feed v1\x00"

var ErrNoUpdate = errors.New("Обновление для этого устройства не требуется")
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$`)
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

type Version [4]uint16

func ParseVersion(s string) (Version, error) {
	var v Version
	if !versionPattern.MatchString(s) {
		return v, errors.New("Некорректная четырёхчастная версия")
	}
	for i, s := range strings.Split(s, ".") {
		n, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return v, err
		}
		v[i] = uint16(n)
	}
	return v, nil
}
func (v Version) Compare(other Version) int {
	for i := range v {
		if v[i] < other[i] {
			return -1
		}
		if v[i] > other[i] {
			return 1
		}
	}
	return 0
}

type Artifact struct {
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
	Version     string `json:"version"`
	VersionCode int64  `json:"versionCode,omitempty"`
	MinSDK      int    `json:"minSdk,omitempty"`
	Filename    string `json:"filename"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	URL         string `json:"url"`
}
type Source struct {
	Platform string `json:"platform"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256"`
	URL      string `json:"url"`
}
type Feed struct {
	Schema      int        `json:"schema"`
	Channel     string     `json:"channel"`
	Release     string     `json:"release"`
	Sequence    uint64     `json:"sequence"`
	PublishedAt time.Time  `json:"publishedAt"`
	ExpiresAt   time.Time  `json:"expiresAt"`
	Notes       string     `json:"notes"`
	Artifacts   []Artifact `json:"artifacts"`
	Sources     []Source   `json:"sources"`
}
type envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func strictJSON(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("Лишние данные после JSON")
	}
	return nil
}

// Verify authenticates the exact payload bytes before parsing any artifact URL.
// The public key must be pinned by the distributor, never obtained from the feed.
func Verify(data []byte, key ed25519.PublicKey, now time.Time, lastSequence uint64) (Feed, error) {
	feed, err := decodeSigned(data, key)
	if err != nil {
		return Feed{}, err
	}
	if err = feed.Validate(now, lastSequence); err != nil {
		return Feed{}, err
	}
	return feed, nil
}

// VerifyHistorical authenticates old published metadata for server-side version
// comparison only. Clients must use Verify with the current clock instead.
func VerifyHistorical(data []byte, key ed25519.PublicKey) (Feed, error) {
	feed, err := decodeSigned(data, key)
	if err != nil {
		return Feed{}, err
	}
	if err = feed.Validate(feed.PublishedAt, 0); err != nil {
		return Feed{}, err
	}
	return feed, nil
}

func decodeSigned(data []byte, key ed25519.PublicKey) (Feed, error) {
	var feed Feed
	if len(key) != ed25519.PublicKeySize || len(data) > MaxFeedBytes {
		return feed, errors.New("Некорректный ключ или размер списка обновлений")
	}
	var wrapped envelope
	if err := strictJSON(data, &wrapped); err != nil {
		return feed, err
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(wrapped.Payload)
	if err != nil {
		return feed, errors.New("Некорректный payload обновления")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(wrapped.Signature)
	if err != nil || !ed25519.Verify(key, append([]byte(signingContext), payload...), signature) {
		return feed, errors.New("Подпись списка обновлений не совпала")
	}
	if err := strictJSON(payload, &feed); err != nil {
		return Feed{}, err
	}
	return feed, nil
}

func (f Feed) Validate(now time.Time, lastSequence uint64) error {
	if f.Schema != 1 || f.Channel != "stable" || !idPattern.MatchString(f.Release) || f.Sequence == 0 || f.Sequence < lastSequence {
		return errors.New("Неподдерживаемый канал или устаревший список обновлений")
	}
	if f.PublishedAt.IsZero() || f.PublishedAt.After(now.Add(10*time.Minute)) || !f.ExpiresAt.After(now) ||
		!f.ExpiresAt.After(f.PublishedAt) || f.ExpiresAt.Sub(f.PublishedAt) > 366*24*time.Hour {
		return errors.New("Срок действия списка обновлений истёк или указан неверно")
	}
	if len(f.Notes) > 8000 || strings.ContainsRune(f.Notes, 0) || len(f.Artifacts) == 0 || len(f.Artifacts) > 8 || len(f.Sources) > 8 {
		return errors.New("Некорректное описание релиза")
	}
	sources := map[string]bool{}
	for _, s := range f.Sources {
		if (s.Platform != "windows" && s.Platform != "android") || sources[s.Platform] || !validDownload(s.URL, s.SHA256, s.Bytes) {
			return errors.New("Некорректный архив соответствующих исходников")
		}
		sources[s.Platform] = true
	}
	seen := map[string]bool{}
	for _, a := range f.Artifacts {
		if _, err := ParseVersion(a.Version); err != nil {
			return err
		}
		if !validDownload(a.URL, a.SHA256, a.Bytes) || !sources[a.Platform] || seen[a.Platform+"/"+a.Arch] {
			return errors.New("Некорректный файл релиза или отсутствуют исходники")
		}
		seen[a.Platform+"/"+a.Arch] = true
		switch a.Platform {
		case "windows":
			if a.Arch != "x64" || a.Filename != "MiniRoute-Setup.exe" || a.VersionCode != 0 || a.MinSDK != 0 {
				return errors.New("Неверный Windows-установщик")
			}
		case "android":
			if a.Arch != "arm64-v8a" || a.Filename != "MiniRoute.apk" || a.VersionCode < 1 || a.VersionCode > 2100000000 || a.MinSDK < 34 || a.MinSDK > 100 {
				return errors.New("Неверный Android APK")
			}
		default:
			return errors.New("Неизвестная платформа релиза")
		}
	}
	return nil
}

func validDownload(raw, hash string, size int64) bool {
	digest, err := hex.DecodeString(hash)
	if err != nil || len(digest) != 32 || hash != strings.ToLower(hash) || size < 1 || size > 512*1024*1024 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 4096 || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.Hostname() == "" || u.Path == "" || u.RawQuery != "" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.ContainsAny(host, "\\%") {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return false
		}
	}
	return true
}

// Select never permits a version downgrade. Android additionally requires a
// higher versionCode; a release for a newer OS is not offered to older devices.
func (f Feed) Select(platform, arch, current string, currentCode int64, sdk int) (Artifact, error) {
	installed, err := ParseVersion(current)
	if err != nil {
		return Artifact{}, err
	}
	for _, a := range f.Artifacts {
		if a.Platform != platform || a.Arch != arch {
			continue
		}
		target, err := ParseVersion(a.Version)
		if err != nil {
			return Artifact{}, err
		}
		if target.Compare(installed) <= 0 || platform == "android" && (a.VersionCode <= currentCode || sdk < a.MinSDK) {
			return Artifact{}, ErrNoUpdate
		}
		return a, nil
	}
	return Artifact{}, ErrNoUpdate
}

// Sign is used by release tooling with a separately provisioned private key.
// No key generation or key storage takes place in this package.
func Sign(f Feed, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("Нет ключа подписи релизов")
	}
	if err := f.Validate(now, 0); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(key, append([]byte(signingContext), payload...))
	raw, err := json.Marshal(envelope{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(signature)})
	if len(raw) > MaxFeedBytes {
		return nil, errors.New("Список обновлений слишком большой")
	}
	return raw, err
}
