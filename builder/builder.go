package builder

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/buth/longshore/lock"
)

type Builder struct {
	path, registryPrefix, slackURL string
	users                          []string
	lock                           lock.Lock
}

func NewBuilder(path, registryPrefix string, users []string, slackURL string) *Builder {
	return &Builder{
		lock:           lock.NewMemoryLock(),
		path:           path,
		registryPrefix: registryPrefix,
		users:          users,
		slackURL:       slackURL,
	}
}

func (b *Builder) slackf(format string, args ...interface{}) error {

	payload := make(map[string]string)
	payload["text"] = fmt.Sprintf(format, args...)

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	response, err := http.PostForm(b.slackURL, url.Values{"payload": {string(payloadJson)}})
	if err != nil {
		return err
	}

	if response.StatusCode >= 400 {
		return errors.New("couldn't message Slack")
	}

	return nil
}

func (b *Builder) userAllowed(user string) bool {
	for _, allowedUser := range b.users {
		if allowedUser == user {
			return true
		}
	}
	return false
}

func (b *Builder) exec(cwd, command string, args ...string) error {

	// Setup the command and try to start it.
	cmd := exec.Command(command, args...)
	cmd.Dir = cwd
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	// Set a reasonable timeout.
	go func() {
		time.Sleep(5 * time.Minute)
		if err := cmd.Process.Kill(); err != nil {
			log.Println(err)
		}
	}()

	// Wait for the command to exit, one way or another.
	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}

func (b *Builder) keyGen(name string, out io.Writer) error {

	// Get the build lock for the given repository.
	b.lock.Lock(name)
	defer b.lock.Unlock(name)

	// Generate a new key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Private key generation process as shown here:
	// http://golang.org/src/crypto/tls/generate_cert.go

	// Open the file for writing.
	keyOut, err := os.OpenFile("/tmp/key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	// Create a block object from the private key and PEM-encode it into the
	// file.
	privateBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(keyOut, privateBlock); err != nil {
		return err
	}

	if err := keyOut.Close(); err != nil {
		return err
	}

	// Public key.
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	// Write the marshaled key to the writer.
	if _, err := out.Write(ssh.MarshalAuthorizedKey(publicKey)); err != nil {
		return err
	}

	return nil
}

func (b *Builder) build(payload Payload) error {

	// Get the build lock for the given repository. All refs are built using
	// the same lock.
	b.lock.Lock(payload.Repository.FullName)
	defer b.lock.Unlock(payload.Repository.FullName)

	// Initialize the cache directory.
	cacheDir := filepath.Join(b.path, payload.Repository.FullName)
	if _, err := os.Stat(cacheDir); err != nil {
		if os.IsNotExist(err) {

			// Establish an initial clone of the repository.
			cmd := exec.Command("git", "clone", payload.Repository.SSHURL, cacheDir)
			if err := cmd.Run(); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// Reset the cache.
	if err := b.exec(cacheDir, "git", "fetch", "origin"); err != nil {
		return err
	}

	// Reset the cache.
	if err := b.exec(cacheDir, "git", "reset", "--hard", payload.HeadCommit.ID); err != nil {
		return err
	}

	// Clean the cache.
	if err := b.exec(cacheDir, "git", "clean", "-d", "-x", "-f"); err != nil {
		return err
	}

	// Set a docker tag based on the git ref.
	var tag string
	switch payload.Ref {
	case "refs/heads/master":
		tag = "latest"
	case "refs/heads/develop":
		tag = "staging"
	default:
		components := strings.Split(payload.Ref, "/")
		tag = components[len(components)-1]
	}

	// Set the image name.
	image := fmt.Sprintf("%s/%s:%s", b.registryPrefix, payload.Repository.Name, tag)

	// Try the Docker build.
	if err := b.exec(cacheDir, "docker", "build", "-t", image, "."); err != nil {
		return err
	}

	// Try the Docker build.
	if err := b.exec(cacheDir, "docker", "push", image); err != nil {
		return err
	}

	return nil
}

func (b *Builder) ServeWebhook(w http.ResponseWriter, r *http.Request) {

	var payload Payload
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&payload); err != nil {

		// HTTP: Bad request.
		fmt.Fprintf(w, "parse error: %s", err.Error())
		w.WriteHeader(400)
		return
	}

	// Verify that this repository is one we can build.
	if !b.userAllowed(payload.Repository.Owner.Name) {

		// Report an unauthorized build request.
		log.Printf(payload.Message("rejected build request"))
		w.WriteHeader(401)
		return
	}

	// Log acceptance.
	log.Printf(payload.Message("accepted build request"))

	if err := b.slackf("Received request to build *<%s|%s>*:%s.", payload.Repository.URL, payload.Repository.FullName, payload.Ref); err != nil {
		log.Println(err)
	}

	// Start a Go routine to handle the build.
	go func() {
		if err := b.build(payload); err != nil {
			if err := b.slackf("Error building *<%s|%s>*:%s!\n%s", payload.Repository.URL, payload.Repository.FullName, payload.Ref, err.Error()); err != nil {
				log.Println(err)
			}
		} else {
			if err := b.slackf("Successfully built and pushed *<%s|%s>*:%s!", payload.Repository.URL, payload.Repository.FullName, payload.Ref); err != nil {
				log.Println(err)
			}
		}
	}()

	// HTTP: Accepted.
	w.WriteHeader(202)
}

func (b *Builder) ServeKey(w http.ResponseWriter, r *http.Request) {

	// The URL path should match a path on GitHub.
	components := strings.Split(r.URL.Path, "/")
	if len(components) != 3 {
		w.WriteHeader(401)
		return
	}

	// Verify that this repository is one we can build.
	if !b.userAllowed(components[1]) {
		w.WriteHeader(401)
		return
	}

	name := strings.Join(components[1:], "/")
	if err := b.keyGen(name, w); err != nil {
		if err := b.slackf("Error adding a :key: for *<https://github.com/%s|%s>*!\n_%s_", name, name, err.Error()); err != nil {
			log.Println(err)
		}
	} else {
		if err := b.slackf("Added a :key: for *<https://github.com/%s|%s>*.", name, name); err != nil {
			log.Println(err)
		}
	}
}

type BuilderError struct {
	err, output string
}

func (b BuilderError) Error() string {
	return b.err
}
