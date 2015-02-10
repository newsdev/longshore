package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/buth/longshore/builder"
)

// containment
var Config struct {
	WebhookAddress, KeyAddress, CachePath, KeyPath, RegistryPrefix, Users, Branches, SlackURL string
}

func init() {
	flag.StringVar(&Config.WebhookAddress, "w", ":5000", "webhook listen address")
	flag.StringVar(&Config.KeyAddress, "k", "127.0.0.1:5001", "key listen address")
	flag.StringVar(&Config.CachePath, "p", "/tmp/longshore/cache", "root path for git caches")
	flag.StringVar(&Config.KeyPath, "q", "/tmp/longshore/keys", "root path for private keys")
	flag.StringVar(&Config.RegistryPrefix, "r", "", "registry prefix")
	flag.StringVar(&Config.Users, "u", "", "users")
	flag.StringVar(&Config.Branches, "b", "master,develop", "branches")
	flag.StringVar(&Config.SlackURL, "s", os.Getenv("SLACK_URL"), "slack URL")
}

func status(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	fmt.Fprint(w, "ok")
}

func main() {
	flag.Parse()

	if Config.SlackURL != "" {
		log.Printf("Slack URL: %s", Config.SlackURL)
	}

	b := builder.NewBuilder(Config.CachePath, Config.KeyPath, Config.RegistryPrefix, strings.Split(Config.Users, ","), strings.Split(Config.Branches, ","), Config.SlackURL)

	err := make(chan error)

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/status", status)
		mux.HandleFunc("/", b.ServeWebhook)
		server := &http.Server{Addr: Config.WebhookAddress, Handler: mux}
		err <- server.ListenAndServe()
	}()

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/status", status)
		mux.HandleFunc("/", b.ServeKey)
		server := &http.Server{Addr: Config.KeyAddress, Handler: mux}
		err <- server.ListenAndServe()
	}()

	panic(<-err)
}
