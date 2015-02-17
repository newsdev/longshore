package builder

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/buth/longshore/lock"
)

const (
	DockerIgnore = `.dockerignore
.DS_Store
.git
.gitignore
.ruby*
Dockerfile
Makefile
README*
tmp
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

func (b *Builder) build(payload Payload) error {

	// Get the build lock for the given repository. All refs are built using
	// the same lock.
	b.lock.Lock(payload.Repository.FullName)
	defer b.lock.Unlock(payload.Repository.FullName)

	// Set the git SSH environment variable.
	gitSSH := map[string]string{
		"GIT_SSH": filepath.Join(b.keyPath, payload.Repository.FullName, "ssh.sh"),
	}

	// Initialize the cache directory.
	cacheDir := filepath.Join(b.cachePath, payload.Repository.FullName)
	cacheGitDir := filepath.Join(cacheDir, ".git")
	if _, err := os.Stat(cacheGitDir); err != nil {
		if os.IsNotExist(err) {

			if err := os.MkdirAll(cacheDir, 0700); err != nil {
				return err
			}

			// Establish an initial clone of the repository.
			if err := Exec(cacheDir, gitSSH, "git", "clone", payload.Repository.SSHURL, "."); err != nil {
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
	if err := Exec(cacheDir, gitSSH, "git", "reset", "--hard", payload.HeadCommit.ID); err != nil {
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

	// Check for a .dockerignore file.
	dockerignore := filepath.Join(cacheDir, ".dockerignore")
	if _, err := os.Stat(dockerignore); err != nil {
		if os.IsNotExist(err) {
			if err := ioutil.WriteFile(dockerignore, []byte(DockerIgnore), 0644); err != nil {
				return err
			}
		} else {
			return err
		}
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

	// Set the image name.
	image := fmt.Sprintf("%s/%s:%s", b.registryPrefix, payload.Repository.Name, payload.Tag())

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
		w.WriteHeader(401)
		return
	}

	// Check if this is one of the branches we are supposed to build. This is to
	// say, tags are never built.
	if !b.branchAllowed(payload.Branch()) {
		w.WriteHeader(200)
		return
	}

	messageReceived := &Message{Text: fmt.Sprintf("Starting a new build in response to a push from <https://github.com/%s|%s>.", payload.Pusher.Name, payload.Pusher.Name)}
	messageReceived.Attatch(payload.Attatchment())
	if err := messageReceived.Send(b.slackURL); err != nil {
		log.Println(err)
	}

	// Start a Go routine to handle the build.
	go func() {
		if err := b.build(payload); err != nil {
			messageErr := &Message{Text: "Caught an error during a build."}
			messageErr.Attatch(payload.Attatchment())

			if execErr, ok := err.(ExecError); ok {
				messageErr.Attatch(execErr.Attatchment())
			} else {
				// TODO: Handle non-exec errors.
			}

			if err := messageErr.Send(b.slackURL); err != nil {
				log.Println(err)
			}
		} else {
			messageErr := &Message{Text: "Successfully built an image and pushed it to your Docker registry!"}
			messageErr.Attatch(payload.Attatchment())
			messageErr.Attatch(&Attatchment{
				AuthorName: "Docker Registry",
				AuthorIcon: "https://d3oypxn00j2a10.cloudfront.net/0.14.4/img/universal/official-repository-icon.png",
				Title:      fmt.Sprintf("%s/%s", b.registryPrefix, payload.Repository.Name),
				Text:       fmt.Sprintf("To pull the updated image:\n```\ndocker pull %s/%s:%s\n```", b.registryPrefix, payload.Repository.Name, payload.Tag()),
				MarkdownIn: []string{"text"},
				Fields: []*Field{
					&Field{
						Title: "Docker Image",
						Value: fmt.Sprintf("%s/%s", b.registryPrefix, payload.Repository.Name),
						Short: true,
					},
					&Field{
						Title: "Docker Tag",
						Value: payload.Tag(),
						Short: true,
					},
				},
			})

			if err := messageErr.Send(b.slackURL); err != nil {
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
