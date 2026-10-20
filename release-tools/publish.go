package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type asset struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	State string `json:"state"`
}
type release struct {
	ID         int64   `json:"id"`
	Tag        string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []asset `json:"assets"`
}
type github struct {
	repo, token string
	client      *http.Client
}

var publisherTransport http.RoundTripper = http.DefaultTransport

func newGitHub(repo, token string) *github {
	return &github{repo, token, &http.Client{Transport: publisherTransport, Timeout: 20 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" || req.URL.User != nil {
			return errors.New("Unsafe redirect")
		}
		switch req.URL.Hostname() {
		case "api.github.com", "uploads.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com":
		default:
			return errors.New("Unknown download host")
		}
		if req.URL.Hostname() != "api.github.com" && req.URL.Hostname() != "uploads.github.com" {
			req.Header.Del("Authorization")
		}
		return nil
	}}}
}
func (g *github) request(method, path string, body []byte, accept string) (*http.Response, error) {
	host := "https://api.github.com"
	if strings.HasPrefix(path, "UPLOAD:") {
		host = "https://uploads.github.com"
		path = strings.TrimPrefix(path, "UPLOAD:")
	}
	req, err := http.NewRequest(method, host+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("User-Agent", "MiniRoute-release-publisher")
	req.Header.Set("Accept", accept)
	req.Header.Set("Content-Type", "application/json")
	return g.client.Do(req)
}
func (g *github) json(method, path string, body any, out any) error {
	var b []byte
	var err error
	if body != nil {
		b, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	r, err := g.request(method, path, b, "application/vnd.github+json")
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return fmt.Errorf("GitHub HTTP %d", r.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(r.Body, 1024*1024)).Decode(out)
	}
	return nil
}
func (g *github) download(a asset, limit int64) (io.ReadCloser, error) {
	if a.State != "uploaded" || a.Size < 1 || a.Size > limit {
		return nil, errors.New("Incomplete or oversized release asset")
	}
	r, err := g.request("GET", fmt.Sprintf("/repos/%s/releases/assets/%d", g.repo, a.ID), nil, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	if r.StatusCode != 200 {
		r.Body.Close()
		return nil, fmt.Errorf("Asset HTTP %d", r.StatusCode)
	}
	return r.Body, nil
}
func (g *github) smallAsset(a asset, limit int64) ([]byte, error) {
	r, err := g.download(a, limit)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if len(b) > int(limit) {
		return nil, errors.New("Asset too large")
	}
	return b, err
}
func findAsset(r release, name string) (asset, error) {
	var found *asset
	for _, a := range r.Assets {
		if a.Name == name {
			if found != nil {
				return asset{}, errors.New("Duplicate asset")
			}
			copy := a
			found = &copy
		}
	}
	if found == nil {
		return asset{}, fmt.Errorf("Missing %s", name)
	}
	return *found, nil
}
func checkAssetNames(r release, allowed map[string]bool) error {
	if len(r.Assets) != len(allowed) {
		return errors.New("Unexpected release assets")
	}
	seen := map[string]bool{}
	for _, a := range r.Assets {
		if !allowed[a.Name] || seen[a.Name] || a.State != "uploaded" {
			return errors.New("Unexpected, duplicate or incomplete release asset")
		}
		seen[a.Name] = true
	}
	return nil
}

func checkAdvance(previous, next Feed) error {
	changed := false
	for _, old := range previous.Artifacts {
		var newer *Artifact
		for _, a := range next.Artifacts {
			if a.Platform == old.Platform && a.Arch == old.Arch {
				copy := a
				newer = &copy
				break
			}
		}
		if newer == nil {
			return errors.New("Previously supported platform missing")
		}
		a, _ := ParseVersion(old.Version)
		b, _ := ParseVersion(newer.Version)
		cmp := b.Compare(a)
		if cmp < 0 || newer.VersionCode < old.VersionCode || cmp == 0 && newer.SHA256 != old.SHA256 || old.Platform == "android" && cmp > 0 && newer.VersionCode <= old.VersionCode {
			return errors.New("Version downgrade or changed binary without version increment")
		}
		changed = changed || cmp > 0
	}
	if !changed {
		return errors.New("No newer platform version")
	}
	return nil
}
func run() error {
	repo := os.Getenv("MINIROUTE_REPOSITORY")
	if repo == "" || repo != os.Getenv("GITHUB_REPOSITORY") {
		return errors.New("Repository mismatch")
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("MINIROUTE_FEED_SIGNING_KEY"))
	if err != nil || len(key) != 64 {
		return errors.New("Release signing key unavailable")
	}
	defer clear(key)
	pinned, err := base64.StdEncoding.DecodeString(os.Getenv("MINIROUTE_FEED_PUBLIC_KEY"))
	if err != nil || !bytes.Equal(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), pinned) {
		return errors.New("Signing key does not match public pin")
	}
	buildKey, err := base64.StdEncoding.DecodeString(os.Getenv("MINIROUTE_BUILD_PUBLIC_KEY"))
	if err != nil || len(buildKey) != 32 {
		return errors.New("Build verification key unavailable")
	}
	now := time.Now().UTC()
	if os.Getenv("MINIROUTE_SELF_TEST") == "true" {
		f := Feed{Schema: 1, Channel: "stable", Release: "self-test", Sequence: 1, PublishedAt: now, ExpiresAt: now.Add(time.Hour),
			Artifacts: []Artifact{{Platform: "windows", Arch: "x64", Version: "0.0.0.0", Filename: "MiniRoute-Setup.exe", Bytes: 1, SHA256: strings.Repeat("a", 64), URL: "https://github.com/" + repo + "/releases/download/self-test/MiniRoute-Setup.exe"}},
			Sources:   []Source{{Platform: "windows", Bytes: 1, SHA256: strings.Repeat("a", 64), URL: "https://github.com/" + repo + "/releases/download/self-test/MiniRoute-source.zip"}}}
		raw, err := Sign(f, ed25519.PrivateKey(key), now)
		if err != nil {
			return err
		}
		if _, err = Verify(raw, ed25519.PublicKey(pinned), now, 0); err != nil {
			return err
		}
		fmt.Println("Self-test PASS: key pin and signature verified; no assets uploaded or releases published.")
		return nil
	}
	platform := os.Getenv("MINIROUTE_PLATFORM")
	if platform != "" && platform != "windows" && platform != "android" {
		return errors.New("Invalid pinned platform")
	}
	if (platform == "" || platform == "windows") && os.Getenv("MINIROUTE_WINDOWS_TESTED") != "true" || (platform == "" || platform == "android") && os.Getenv("MINIROUTE_ANDROID_TESTED") != "true" {
		return errors.New("Manual Windows and Android acceptance required")
	}
	id, err := strconv.ParseInt(os.Getenv("MINIROUTE_RELEASE_ID"), 10, 64)
	if err != nil || id < 1 {
		return errors.New("Invalid draft id")
	}
	g := newGitHub(repo, os.Getenv("GITHUB_TOKEN"))
	prefix := "/repos/" + repo
	var draft release
	if err = g.json("GET", fmt.Sprintf("%s/releases/%d", prefix, id), nil, &draft); err != nil {
		return err
	}
	if !draft.Draft || draft.Prerelease || len(draft.Assets) < 3 || len(draft.Assets) > 6 {
		return errors.New("Only a complete stable draft can be published")
	}
	signed, err := findAsset(draft, "candidate.json")
	if err != nil {
		return err
	}
	raw, err := g.smallAsset(signed, MaxFeedBytes)
	if err != nil {
		return err
	}
	candidate, err := Verify(raw, ed25519.PublicKey(buildKey), now, 0)
	if err != nil {
		return fmt.Errorf("Build attestation rejected: %w", err)
	}
	expected := 2
	if platform != "" {
		expected = 1
	}
	if candidate.Release != draft.Tag || len(candidate.Artifacts) != expected || len(candidate.Sources) != expected || (platform != "" && (candidate.Artifacts[0].Platform != platform || candidate.Sources[0].Platform != platform)) || len(draft.Assets) < 2*expected+1 {
		return errors.New("Release/build mismatch")
	}
	checks := map[string]struct {
		bytes int64
		hash  string
	}{}
	for _, a := range candidate.Artifacts {
		if a.URL != "https://github.com/"+repo+"/releases/download/"+draft.Tag+"/"+a.Filename {
			return errors.New("Unexpected artifact origin")
		}
		checks[a.Filename] = struct {
			bytes int64
			hash  string
		}{a.Bytes, a.SHA256}
	}
	for _, s := range candidate.Sources {
		name := "MiniRoute-source.zip"
		if s.Platform == "android" {
			name = "MiniRoute-Android-source.zip"
		}
		if s.URL != "https://github.com/"+repo+"/releases/download/"+draft.Tag+"/"+name {
			return errors.New("Unexpected source origin")
		}
		checks[name] = struct {
			bytes int64
			hash  string
		}{s.Bytes, s.SHA256}
	}
	allowed := map[string]bool{"candidate.json": true}
	for name := range checks {
		allowed[name] = true
	}
	if err = checkAssetNames(draft, allowed); err != nil {
		return err
	}
	for name, expected := range checks {
		a, err := findAsset(draft, name)
		if err != nil {
			return err
		}
		if a.Size != expected.bytes {
			return errors.New("Asset length mismatch")
		}
		stream, err := g.download(a, 512*1024*1024)
		if err != nil {
			return err
		}
		hash := sha256.New()
		n, err := io.Copy(hash, io.LimitReader(stream, expected.bytes+1))
		stream.Close()
		if err != nil || n != expected.bytes || hex.EncodeToString(hash.Sum(nil)) != expected.hash {
			return fmt.Errorf("Hash mismatch: %s", name)
		}
	}
	var latest release
	latestResponse, err := g.request("GET", prefix+"/releases/latest", nil, "application/vnd.github+json")
	if err != nil {
		return err
	}
	status := latestResponse.StatusCode
	if status == 200 {
		err = json.NewDecoder(io.LimitReader(latestResponse.Body, 1024*1024)).Decode(&latest)
	}
	latestResponse.Body.Close()
	if err != nil {
		return err
	}
	if status != 200 && status != 404 {
		return fmt.Errorf("Latest release HTTP %d", status)
	}
	if status == 200 {
		a, err := findAsset(latest, "MiniRoute-updates.json")
		if err != nil {
			return err
		}
		b, err := g.smallAsset(a, MaxFeedBytes)
		if err != nil {
			return err
		}
		previous, err := VerifyHistorical(b, ed25519.PublicKey(pinned))
		if err != nil {
			return err
		}
		if err = checkAdvance(previous, candidate); err != nil {
			return err
		}
		if candidate.Sequence <= previous.Sequence {
			candidate.Sequence = previous.Sequence + 1
		}
	}
	candidate.PublishedAt = now
	candidate.ExpiresAt = now.Add(365 * 24 * time.Hour)
	if candidate.Sequence < uint64(now.UnixMicro()) {
		candidate.Sequence = uint64(now.UnixMicro())
	}
	feed, err := Sign(candidate, ed25519.PrivateKey(key), now)
	if err != nil {
		return err
	}
	if _, err = findAsset(draft, "MiniRoute-updates.json"); err == nil {
		return errors.New("Signed feed already present: inspect interrupted draft before retrying")
	}
	response, err := g.request("POST", fmt.Sprintf("UPLOAD:%s/releases/%d/assets?name=MiniRoute-updates.json", prefix, id), feed, "application/vnd.github+json")
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != 201 {
		return fmt.Errorf("Feed upload HTTP %d", response.StatusCode)
	}
	var refreshed release
	if err = g.json("GET", fmt.Sprintf("%s/releases/%d", prefix, id), nil, &refreshed); err != nil {
		return err
	}
	if !refreshed.Draft || refreshed.Tag != draft.Tag {
		return errors.New("Draft changed during verification")
	}
	allowed["MiniRoute-updates.json"] = true
	if err = checkAssetNames(refreshed, allowed); err != nil {
		return err
	}
	// Publication is the final write, after attestation and every file hash.
	if err = g.json("PATCH", fmt.Sprintf("%s/releases/%d", prefix, id), map[string]any{"draft": false, "prerelease": false, "make_latest": "true"}, nil); err != nil {
		return err
	}
	fmt.Println("Published verified public release " + candidate.Release)
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
