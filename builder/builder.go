package builder

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
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

var (
	AppNameMissingError   = errors.New("missing app name")
	MongoDBSessionMissing = errors.New("no MongoDB session information was provided")
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

		b.mongoDBSession = session

		allIndicies := map[string][]mgo.Index{
			"builds": []mgo.Index{
				mgo.Index{
					Key: []string{"-updated", "app_name", "repository_user", "repository_name", "branch"},
				},
			},
			"apps": []mgo.Index{
				mgo.Index{
					Key:    []string{"name"},
					Unique: true,
				},
			},
			"repositories": []mgo.Index{
				mgo.Index{
					Key: []string{"app_name"},
				},
				mgo.Index{
					Key:    []string{"app_name", "user", "name"},
					Unique: true,
				},
			},
			"services": []mgo.Index{
				mgo.Index{
					Key:    []string{"app_name", "repository_user", "repository_name", "name", "environment"},
					Unique: true,
				},
			},
		}

		if err := b.mongodbDo(func(db *mgo.Database) error {
			for collection, indicies := range allIndicies {
				for _, index := range indicies {
					if err := db.C(collection).EnsureIndex(index); err != nil {
						return err
					}
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	return b, nil
}

func (b *Builder) mongodbDo(action func(*mgo.Database) error) error {

	// Make sure there is a root session.
	if b.mongoDBSession == nil {
		return MongoDBSessionMissing
	}

	// Get a new session and defer its closing.
	session := b.mongoDBSession.Copy()
	defer session.Close()

	// Run the action, returning any error.
	return action(session.DB(b.config.MongoDBDialInfo.Database))
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

	if err := b.mongodbDo(func(db *mgo.Database) error {
		return db.C("builds").Insert(bson.M{
			"branch":          branch,
			"commit":          commit,
			"pusher":          pusher,
			"repository_name": repository,
			"status":          "pending",
			"tag":             tag,
			"updated":         time.Now(),
			"repository_user": user,
		})
	}); err != nil {
		log.Println(err)
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
	if err := b.build(user, repository, branch, commit, tag); err != nil {

		var errorOuput string
		if execErr, ok := err.(ExecError); ok {
			errorOuput = execErr.Output
		}

		if err := b.mongodbDo(func(db *mgo.Database) error {
			return db.C("builds").Insert(bson.M{
				"pusher":          pusher,
				"tag":             tag,
				"status":          "error",
				"error":           err.Error(),
				"errorOutput":     errorOuput,
				"repository_user": user,
				"repository_name": repository,
				"branch":          branch,
				"commit":          commit,
				"updated":         time.Now(),
			})
		}); err != nil {
			log.Println(err)
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
		if err := b.mongodbDo(func(db *mgo.Database) error {
			return db.C("builds").Insert(bson.M{
				"pusher":          pusher,
				"tag":             tag,
				"status":          "success",
				"repository_user": user,
				"repository_name": repository,
				"branch":          branch,
				"commit":          commit,
				"updated":         time.Now(),
			})
		}); err != nil {
			log.Println(err)
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

func (b *Builder) build(user, repository, branch, commit, tag string) error {

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

	// Check if we need to handle a Longfile.
	longshorefile := filepath.Join(cacheDir, "Longshorefile")
	if _, err := os.Stat(longshorefile); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {

		// Open the Longfile. If there isn't one, we need to return an error
		// anyway.
		longshorefileFile, err := os.Open(longshorefile)
		if err != nil {
			return err
		}

		longshorefileBytes, err := ioutil.ReadAll(longshorefileFile)
		if err != nil {
			return err
		}

		var longshorefileData map[string]string
		json.Unmarshal(longshorefileBytes, &longshorefileData)
		if len(longshorefileData["name"]) == 0 {
			return AppNameMissingError
		}

		if err := b.mongodbDo(func(db *mgo.Database) error {
			_, err := db.C("apps").Upsert(
				bson.M{
					"name": longshorefileData["name"],
				},
				longshorefileData,
			)
			return err
		}); err != nil {
			log.Println(err)
		}

		if err := b.mongodbDo(func(db *mgo.Database) error {
			_, err := db.C("repositories").Upsert(
				bson.M{
					"app_name": longshorefileData["name"],
					"user":     user,
					"name":     repository,
				},
				bson.M{
					"app_name": longshorefileData["name"],
					"user":     user,
					"name":     repository,
				},
			)
			return err
		}); err != nil {
			log.Println(err)
		}

		// Determine the services environment to use.
		var servicesEnvironment string
		log.Println(branch)
		switch branch {
		case "master":
			servicesEnvironment = "prd"
		case "develop":
			servicesEnvironment = "stg"
		}

		// Check if we need to handle services.
		servicesDir := filepath.Join(cacheDir, "services", servicesEnvironment)
		if _, err := os.Stat(servicesDir); err != nil {
			if !os.IsNotExist(err) {
				return err
			}
		} else {

			// List all of the service files in the given services directory.
			serviceFiles, err := ioutil.ReadDir(filepath.Join(cacheDir, "services", servicesEnvironment))
			if err != nil {
				return err
			}

			if err := b.mongodbDo(func(db *mgo.Database) error {
				for _, serviceFile := range serviceFiles {
					serviceName := serviceFile.Name()
					if _, err := db.C("services").Upsert(
						bson.M{
							"app_name":        longshorefileData["name"],
							"name":            serviceName,
							"environment":     servicesEnvironment,
							"repository_user": user,
							"repository_name": repository,
						},
						bson.M{
							"app_name":        longshorefileData["name"],
							"name":            serviceName,
							"environment":     servicesEnvironment,
							"repository_user": user,
							"repository_name": repository,
						},
					); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				log.Println(err)
			}
		}
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

func (b *Builder) ServeApps(w http.ResponseWriter, r *http.Request) {

	// Get the user and repository values from mux.
	session := b.mongoDBSession.Copy()
	defer session.Close()

	iter := session.DB(b.config.MongoDBDialInfo.Database).C("apps").Find(bson.M{}).Select(bson.M{"name": 1}).Iter()

	if err := writeAllAsResult(iter, w); err != nil {
		log.Println(err)
		w.WriteHeader(500)
	}
}

func (b *Builder) ServeRepos(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	name := vars["name"]

	// Get the user and repository values from mux.
	session := b.mongoDBSession.Copy()
	defer session.Close()

	iter := session.DB(b.config.MongoDBDialInfo.Database).C("repositories").Find(bson.M{
		"app_name": name,
	}).Select(bson.M{"user": 1, "name": 1}).Iter()

	if err := writeAllAsResult(iter, w); err != nil {
		log.Println(err)
		w.WriteHeader(500)
	}
}

func (b *Builder) ServeServices(w http.ResponseWriter, r *http.Request) {

	// Get the user and repository values from mux.
	vars := mux.Vars(r)
	name := vars["name"]
	user := vars["user"]
	repository := vars["repository"]

	session := b.mongoDBSession.Copy()
	defer session.Close()

	iter := session.DB(b.config.MongoDBDialInfo.Database).C("services").Find(bson.M{
		"app_name":        name,
		"repository_user": user,
		"repository_name": repository,
	}).Select(bson.M{"name": 1, "environment": 1}).Iter()

	if err := writeAllAsResult(iter, w); err != nil {
		log.Println(err)
		w.WriteHeader(500)
	}
}

func (b *Builder) ServeBuilds(w http.ResponseWriter, r *http.Request) {

	// Get the user and repository values from mux.
	vars := mux.Vars(r)
	user := vars["user"]
	repository := vars["repository"]

	session := b.mongoDBSession.Copy()
	defer session.Close()

	iter := session.DB(b.config.MongoDBDialInfo.Database).C("builds").Find(bson.M{
		"repository_user": user,
		"repository_name": repository,
	}).Sort("-updated").Limit(20).Iter()

	if err := writeAllAsResult(iter, w); err != nil {
		log.Println(err)
		w.WriteHeader(500)
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
