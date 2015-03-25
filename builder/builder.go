package builder

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/buth/longshore/github"
	"github.com/buth/longshore/lock"
)

const (
	DockerIgnore = `.git
.gitignore
`
)

type Builder struct {
	cachePath, keyPath, registryPrefix, slackURL string
	users, branches                              []string
	lock                                         lock.Lock
}

func NewBuilder(cachePath, keyPath, registryPrefix string, users, branches []string, slackURL string) *Builder {
	return &Builder{
		lock:           lock.NewMemoryLock(),
		cachePath:      cachePath,
		keyPath:        keyPath,
		registryPrefix: registryPrefix,
		users:          users,
		branches:       branches,
		slackURL:       slackURL,
	}
}

func (b *Builder) userAllowed(user string) bool {
	for _, allowedUser := range b.users {
		if allowedUser == user {
			return true
		}
	}
	return false
}

func (b *Builder) branchAllowed(branch string) bool {
	for _, allowedBranch := range b.branches {
		if allowedBranch == branch {
			return true
		}
	}
	return false
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

	// Initialize the key directory.
	keyDir := filepath.Join(b.keyPath, name)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return err
	}

	// Private key generation process as shown here:
	// http://golang.org/src/crypto/tls/generate_cert.go

	// Open the file for writing.
	keyPath := filepath.Join(keyDir, "key.pem")
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
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

	// Open the file for writing.
	keyWrapperPath := filepath.Join(keyDir, "ssh.sh")
	keyWrapperOut, err := os.OpenFile(keyWrapperPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}

	// Wreite the wrapper script.
	if _, err := io.WriteString(keyWrapperOut, fmt.Sprintf("#!/bin/bash\nssh -i %s $@\n", keyPath)); err != nil {
		return err
	}

	if err := keyWrapperOut.Close(); err != nil {
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

func (b *Builder) build(fullName, name, cloneURL, commit, tag string) error {

	// Get the build lock for the given repository. All refs are built using
	// the same lock.
	b.lock.Lock(fullName)
	defer b.lock.Unlock(fullName)

	// Set the git SSH environment variable.
	gitSSH := map[string]string{
		"GIT_SSH": filepath.Join(b.keyPath, fullName, "ssh.sh"),
	}

	// Initialize the cache directory.
	cacheDir := filepath.Join(b.cachePath, fullName)
	cacheGitDir := filepath.Join(cacheDir, ".git")
	if _, err := os.Stat(cacheGitDir); err != nil {
		if os.IsNotExist(err) {

			if err := os.MkdirAll(cacheDir, 0700); err != nil {
				return err
			}

			// Establish an initial clone of the repository.
			if err := Exec(cacheDir, gitSSH, "git", "clone", cloneURL, "."); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// Reset the cache.
	if err := Exec(cacheDir, gitSSH, "git", "fetch", "origin"); err != nil {
		return err
	}

	// Reset the cache.
	if err := Exec(cacheDir, gitSSH, "git", "reset", "--hard", commit); err != nil {
		return err
	}

	// Clean the cache.
	if err := Exec(cacheDir, gitSSH, "git", "clean", "-d", "-x", "-f"); err != nil {
		return err
	}

	// Open the Dockerfile. If there isn't one, we need to return an error
	// anyway.
	dockerfile, err := os.Open(filepath.Join(cacheDir, "Dockerfile"))
	if err != nil {
		return err
	}

	// Scan the Dockerfile looking for "FROM" directives.
	scanner := bufio.NewScanner(dockerfile)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		components := strings.SplitN(line, " ", 2)
		if len(components) == 2 && components[0] == "FROM" {
			if err := Exec(cacheDir, nil, "docker", "pull", strings.TrimSpace(components[1])); err != nil {
				return err
			}
		}
	}

	// Check for Scanner errors.
	if err := scanner.Err(); err != nil {
		return err
	}

	// Close the Dockerfile.
	if err := dockerfile.Close(); err != nil {
		return err
	}

	// Check for a .dockerignore file.
	dockerignore := filepath.Join(cacheDir, ".dockerignore")
	if _, err := os.Stat(dockerignore); err != nil {
		if os.IsNotExist(err) {
			if err := ioutil.WriteFile(dockerignore, []byte(DockerIgnore), 0600); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	// Set the full Docker image name.
	image := fmt.Sprintf("%s/%s:%s", b.registryPrefix, name, tag)

	// Try the Docker build.
	if err := Exec(cacheDir, nil, "docker", "build", "-t", image, "."); err != nil {
		return err
	}

	// Try the Docker build.
	if err := Exec(cacheDir, nil, "docker", "push", image); err != nil {
		return err
	}

	return nil
}

func (b *Builder) ServeWebhook(w http.ResponseWriter, r *http.Request) {

	// Read the payload into a byte slice.
	payloadBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(400)
		return
	}

	// Attempt to parse the payload as a PullRequestEvent, returning any error
	// as a 400 (Bad Request).
	p := github.Payload{}
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		log.Println(err)
		w.WriteHeader(400)
		return
	}

	// Check that the owner of the repository is allowed to have builds run.
	// Return a 401 (Unauthorized) if they are not.
	if !b.userAllowed(p.Repository.Owner.Name) {
		w.WriteHeader(401)
		return
	}

	// Check whether or not this is a buildable branch.
	var tag string
	switch p.Branch() {
	case "master":
		tag = "latest"
	case "develop":
		tag = "staging"
	default:
		w.WriteHeader(200)
		return
	}

	// Start a Go routine to handle the build.
	go func() {

		messageRecieved := NewMessage()
		messageRecieved.Text = fmt.Sprintf("A new build request was recieved from _%s_.", p.Pusher.Name)
		messageRecievedAttatchment := NewAttatchment()
		messageRecievedAttatchment.Fallback = fmt.Sprintf("%s:%s (%s) → %s:staging", p.Repository.FullName, p.Branch(), p.HeadCommit.ID[:10], p.Repository.Name)
		messageRecievedAttatchment.Text = fmt.Sprintf("*<%s|%s>*:%s (<%s|%s>) → :package: *%s*:staging", p.Repository.URL, p.Repository.FullName, p.Branch(), p.HeadCommit.URL, p.HeadCommit.ID[:10], p.Repository.Name)
		messageRecievedAttatchment.MarkdownIn = []string{"text"}
		messageRecieved.Attatch(messageRecievedAttatchment)
		if err := messageRecieved.Send(b.slackURL); err != nil {
			fmt.Printf("error: %s\n", err.Error())
		}

		// Run the build.
		if err := b.build(p.Repository.FullName, p.Repository.Name, p.Repository.SSHURL, p.HeadCommit.ID, tag); err != nil {

			messageError := NewMessage()
			messageError.Text = fmt.Sprintf("Encountered an error while handling a build request from _%s_.", p.Pusher.Name)
			messageError.Attatch(messageRecievedAttatchment)

			if execErr, ok := err.(ExecError); ok {
				messageError.Attatch(execErr.Attatchment())
			} else {
				messageErrorAttatchment := NewAttatchment()
				messageErrorAttatchment.Fallback = err.Error()
				messageErrorAttatchment.Text = fmt.Sprintf("_%s_", err.Error())
				messageErrorAttatchment.Color = "danger"
				messageError.Attatch(messageErrorAttatchment)
			}
			if err := messageError.Send(b.slackURL); err != nil {
				fmt.Printf("error: %s\n", err.Error())
			}
		}

		// Note that the build was successful.
		messageSuccess := NewMessage()
		messageSuccess.Text = fmt.Sprintf("Successfully processed a build request from _%s_!", p.Pusher.Name)
		messageSuccess.Attatch(messageRecievedAttatchment)
		if err := messageSuccess.Send(b.slackURL); err != nil {
			fmt.Printf("error: %s\n", err.Error())
		}
	}()

	// Since we've accepted the build request but have nothing to report, return
	// a 202 (Accepted).
	w.WriteHeader(202)
}

func (b *Builder) ServeKey(w http.ResponseWriter, r *http.Request) {

	// The URL path should match a path on GitHub.
	components := strings.Split(r.URL.Path, "/")
	if len(components) != 3 {
		w.WriteHeader(400)
		return
	}

	// Verify that this repository is one we can build.
	if !b.userAllowed(components[1]) {
		w.WriteHeader(401)
		return
	}

	name := strings.Join(components[1:], "/")
	message := NewMessage()
	if err := b.keyGen(name, w); err != nil {
		message.Text = fmt.Sprintf("Caught an error setting a :key: for *%s*.", name)

		if execErr, ok := err.(ExecError); ok {
			message.Attatch(execErr.Attatchment())
		} else {
			// TODO: Handle non-exec errors.
		}
	} else {
		message.Text = fmt.Sprintf("Set a new :key: for *%s*!", name)
	}

	// Send the message.
	if err := message.Send(b.slackURL); err != nil {
		log.Println(err)
	}
}

type BuilderError struct {
	err, command, output string
}

func (b BuilderError) Error() string {
	return b.err
}
