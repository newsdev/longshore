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
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/newsdev/longshore/vendor/src/github.com/go-mgo/mgo"
	"github.com/newsdev/longshore/vendor/src/github.com/go-mgo/mgo/bson"

	"github.com/gorilla/mux"
	"github.com/newsdev/longshore/github"
	"github.com/newsdev/longshore/lock"
)

const (
	DockerIgnore = `.git
.gitignore
`
)

type Config struct {
	CachePath, KeyPath, RegistryPrefix, SlackURL string
	Users, Branches                              []string
	MongoDBDialInfo                              *mgo.DialInfo
}

type Builder struct {
	config         *Config
	mongoDBSession *mgo.Session
	lock           lock.Lock
}

func NewBuilder(config *Config) (*Builder, error) {
	b := &Builder{
		config: config,
		lock:   lock.NewMemoryLock(),
	}

	if b.config.MongoDBDialInfo != nil {
		session, err := mgo.DialWithInfo(b.config.MongoDBDialInfo)
		if err != nil {
			return nil, err
		}

		buildsCollection := session.DB(b.config.MongoDBDialInfo.Database).C("builds")

		buildSortIndex := mgo.Index{
			Key: []string{"-updated", "user", "repository", "branch"},
		}

		if err := buildsCollection.EnsureIndex(buildSortIndex); err != nil {
			return nil, err
		}

		b.mongoDBSession = session
	}

	return b, nil
}

func (b *Builder) userAllowed(user string) bool {
	for _, allowedUser := range b.config.Users {
		if allowedUser == user {
			return true
		}
	}
	return false
}

func (b *Builder) branchAllowed(branch string) bool {
	for _, allowedBranch := range b.config.Branches {
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
	keyDir := filepath.Join(b.config.KeyPath, name)
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

func (b *Builder) Build(pusher, user, repository, branch, commit, tag string) {

	repositoryURL := fmt.Sprintf("https://github.com:%s/%s", user, repository)
	commitURL := fmt.Sprintf("https://github.com:%s/%s/commit", user, repository, commit)

	if b.mongoDBSession != nil {
		session := b.mongoDBSession.Copy()

		if err := session.DB(b.config.MongoDBDialInfo.Database).C("builds").Insert(bson.M{
			"pusher":     pusher,
			"tag":        tag,
			"status":     "pending",
			"user":       user,
			"repository": repository,
			"branch":     repository,
			"commit":     commit,
			"updated":    time.Now(),
		}); err != nil {
			log.Println(err)
		}

		session.Close()
	}

	text := fmt.Sprintf("*<%s|%s/%s>*:%s (<%s|%s>) → :package: *%s*:%s", repositoryURL, user, repository, branch, commitURL, commit[:10], repository, tag)

	// Send a Slack message indicating we've recieved a build request.
	messageRecieved := NewMessage()
	messageRecieved.Text = text

	messageRecievedAttatchment := NewAttatchment()
	messageRecievedAttatchment.Fallback = fmt.Sprintf("Recieved a build request from %s.", pusher)
	messageRecievedAttatchment.Text = fmt.Sprintf("Recieved a build request from _%s_.", pusher)
	messageRecievedAttatchment.MarkdownIn = []string{"text"}

	messageRecieved.Attatch(messageRecievedAttatchment)
	if err := messageRecieved.Send(b.config.SlackURL); err != nil {
		fmt.Printf("error: %s\n", err.Error())
	}

	// Run the build.
	if err := b.build(user, repository, commit, tag); err != nil {

		// Note the error in MongoDB if necessary.
		if b.mongoDBSession != nil {
			session := b.mongoDBSession.Copy()

			var errorOuput string
			if execErr, ok := err.(ExecError); ok {
				errorOuput = execErr.Output
			}

			if err := session.DB(b.config.MongoDBDialInfo.Database).C("builds").Insert(bson.M{
				"pusher":      pusher,
				"tag":         tag,
				"status":      "error",
				"error":       err.Error(),
				"errorOutput": errorOuput,
				"user":        user,
				"repository":  repository,
				"branch":      repository,
				"commit":      commit,
				"updated":     time.Now(),
			}); err != nil {
				log.Println(err)
			}

			session.Close()
		}

		messageError := NewMessage()
		messageError.Text = text

		if execErr, ok := err.(ExecError); ok {
			messageError.Attatch(execErr.Attatchment())
		} else {
			messageErrorAttatchment := NewAttatchment()
			messageErrorAttatchment.Fallback = err.Error()
			messageErrorAttatchment.Text = fmt.Sprintf("_%s_", err.Error())
			messageErrorAttatchment.Color = "danger"
			messageErrorAttatchment.MarkdownIn = []string{"text"}
			messageError.Attatch(messageErrorAttatchment)
		}
		if err := messageError.Send(b.config.SlackURL); err != nil {
			fmt.Printf("error: %s\n", err.Error())
		}
	} else {

		// Note the success in MongoDB if necessary.
		if b.mongoDBSession != nil {
			session := b.mongoDBSession.Copy()

			if err := session.DB(b.config.MongoDBDialInfo.Database).C("builds").Insert(bson.M{
				"pusher":     pusher,
				"tag":        tag,
				"status":     "success",
				"user":       user,
				"repository": repository,
				"branch":     repository,
				"commit":     commit,
				"updated":    time.Now(),
			}); err != nil {
				log.Println(err)
			}

			session.Close()
		}

		// Note that the build was successful.
		messageSuccess := NewMessage()
		messageSuccess.Text = text

		messageSuccessAttatchment := NewAttatchment()
		messageSuccessAttatchment.Fallback = fmt.Sprintf("Successfully processed a build request from %s!", pusher)
		messageSuccessAttatchment.Text = fmt.Sprintf("Successfully processed a build request from _%s_!", pusher)
		messageSuccessAttatchment.Color = "good"
		messageSuccessAttatchment.MarkdownIn = []string{"text"}

		messageSuccess.Attatch(messageSuccessAttatchment)
		if err := messageSuccess.Send(b.config.SlackURL); err != nil {
			fmt.Printf("error: %s\n", err.Error())
		}
	}
}

func (b *Builder) build(user, repository, commit, tag string) error {

	fullName := fmt.Sprintf("%s/%s", user, repository)
	cloneURL := fmt.Sprintf("git@github.com:%s/%s.git", user, repository)

	// Get the build lock for the given repository. All refs are built using
	// the same lock.
	b.lock.Lock(fullName)
	defer b.lock.Unlock(fullName)

	// Set the git SSH environment variable.
	gitSSH := map[string]string{
		"GIT_SSH": filepath.Join(b.config.KeyPath, fullName, "ssh.sh"),
	}

	// Initialize the cache directory.
	cacheDir := filepath.Join(b.config.CachePath, fullName)
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
	image := fmt.Sprintf("%s/%s:%s", b.config.RegistryPrefix, repository, tag)

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
	go b.Build(p.Pusher.Name, p.Repository.Owner.Name, p.Repository.Name, p.Branch(), p.HeadCommit.ID, tag)

	// Since we've accepted the build request but have nothing to report, return
	// a 202 (Accepted).
	w.WriteHeader(202)
}

func (b *Builder) ServeBuilds(w http.ResponseWriter, r *http.Request) {

	// Get the user and repository values from mux.
	vars := mux.Vars(r)
	user := vars["user"]
	repository := vars["repository"]

	session := b.mongoDBSession.Copy()
	defer session.Close()

	iter := session.DB(b.config.MongoDBDialInfo.Database).C("builds").Find(bson.M{
		"user":       user,
		"repository": repository,
	}).Sort("-updated").Limit(20).Iter()

	var result []bson.M
	if err := iter.All(&result); err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	if _, err := w.Write(resultBytes); err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}
}

func (b *Builder) ServeBuild(w http.ResponseWriter, r *http.Request) {

	// Get the user and repository values from mux.
	vars := mux.Vars(r)
	user := vars["user"]
	repository := vars["repository"]

	// Check that the owner of the repository is allowed to have builds run.
	// Return a 401 (Unauthorized) if they are not.
	if !b.userAllowed(user) {
		w.WriteHeader(401)
		return
	}

	// Get the pusher, branch and commit values from the query.
	query := r.URL.Query()
	pusher := query.Get("pusher")
	branch := query.Get("branch")
	commit := query.Get("commit")

	// Check whether or not this is a buildable branch.
	var tag string
	switch branch {
	case "master":
		tag = "latest"
	case "develop":
		tag = "staging"
	default:
		w.WriteHeader(200)
		return
	}

	// Start a Go routine to handle the build.
	go b.Build(pusher, user, repository, branch, commit, tag)

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
	if err := message.Send(b.config.SlackURL); err != nil {
		log.Println(err)
	}
}

type BuilderError struct {
	err, command, output string
}

func (b BuilderError) Error() string {
	return b.err
}
