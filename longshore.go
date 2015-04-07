package main // import "github.com/newsdev/longshore"

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/newsdev/longshore/vendor/src/github.com/go-mgo/mgo"

	"github.com/newsdev/longshore/builder"
)

// containment
var Config struct {
	WebhookAddress, KeyAddress, CachePath, KeyPath, RegistryPrefix, Users, Branches string

	// Slack configuration options.
	Slack struct {
		URL string
	}

	// MongoDB configuration options.
	MongoDB struct {
		Servers, Database, Username, Password string
		SSL                                   bool
	}
}

func init() {
	flag.StringVar(&Config.WebhookAddress, "w", ":5000", "webhook listen address")
	flag.StringVar(&Config.KeyAddress, "k", "127.0.0.1:5001", "key listen address")

	flag.StringVar(&Config.CachePath, "p", "/tmp/longshore/cache", "root path for git caches")
	flag.StringVar(&Config.KeyPath, "q", "/tmp/longshore/keys", "root path for private keys")

	flag.StringVar(&Config.RegistryPrefix, "r", "", "registry prefix")

	flag.StringVar(&Config.Users, "u", "", "users")
	flag.StringVar(&Config.Branches, "b", "master,develop", "branches")

	// Slack configuration options.
	flag.StringVar(&Config.Slack.URL, "slack-url", os.Getenv("SLACK_URL"), "slack webhook URL")

	// MongoDB configuration options.
	flag.StringVar(&Config.MongoDB.Servers, "mongodb-servers", os.Getenv("MONGODB_SERVERS"), "comma-seperated list of MongoDB server addresses")
	flag.StringVar(&Config.MongoDB.Database, "mongodb-database", os.Getenv("MONGODB_DATABASE"), "MongoDB database to use")
	flag.StringVar(&Config.MongoDB.Username, "mongodb-username", os.Getenv("MONGODB_USERNAME"), "MongoDB username")
	flag.StringVar(&Config.MongoDB.Password, "mongodb-password", os.Getenv("MONGODB_PASSWORD"), "MongoDB password")
	flag.BoolVar(&Config.MongoDB.SSL, "mongodb-ssl", false, "use SSL for MongoDB connections")
}

func status(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	fmt.Fprint(w, "ok")
}

var f = status

func main() {
	flag.Parse()

	// Construct a builder configuration object.
	config := &builder.Config{
		CachePath:      Config.CachePath,
		KeyPath:        Config.KeyPath,
		RegistryPrefix: Config.RegistryPrefix,
		Users:          strings.Split(Config.Users, ","),
		Branches:       strings.Split(Config.Branches, ","),
		SlackURL:       Config.Slack.URL,
	}

	// Build a MongoDB DialInfo object from the provided flags if a server
	// address was specified.
	if Config.MongoDB.Servers != "" {
		config.MongoDBDialInfo = &mgo.DialInfo{
			Addrs:    strings.Split(Config.MongoDB.Servers, ","),
			Timeout:  time.Second * 10,
			Database: Config.MongoDB.Database,
			Username: Config.MongoDB.Username,
			Password: Config.MongoDB.Password,
		}

		// Check to see if we need to use a TLS dialer.
		if Config.MongoDB.SSL {
			tlsConfig := &tls.Config{}
			config.MongoDBDialInfo.DialServer = func(addr *mgo.ServerAddr) (net.Conn, error) {
				return tls.Dial("tcp", addr.String(), tlsConfig)
			}
		}
	}

	// Create a builder from the configuration.
	b, err := builder.NewBuilder(config)
	if err != nil {
		log.Fatal(err)
	}

	// Create an errors channel so we can panic on any listening error from
	// either server.
	errs := make(chan error)

	// Run the API.
	go func() {
		r := mux.NewRouter()

		// Build a sub-router for POST endpoints.
		p := r.Methods("POST").Subrouter()
		p.HandleFunc("/", b.ServeWebhook).Headers("X-GitHub-Event", "push")

		// Build a sub-router for GET endpoints.
		g := r.Methods("GET").Subrouter()
		g.HandleFunc("/status", status)
		g.HandleFunc("/{user}/{repository}/build", b.ServeBuild)
		g.HandleFunc("/{user}/{repository}/builds", b.ServeBuilds)

		server := &http.Server{Addr: Config.WebhookAddress, Handler: r}
		errs <- server.ListenAndServe()
	}()

	// Run the key generator.
	go func() {
		r := mux.NewRouter()

		// Build a sub-router for GET endpoints.
		g := r.Methods("GET").Subrouter()
		g.HandleFunc("/status", status)
		g.HandleFunc("/{user}/{repository}", b.ServeKey)

		server := &http.Server{Addr: Config.KeyAddress, Handler: r}
		errs <- server.ListenAndServe()
	}()

	log.Fatal(<-errs)
}
