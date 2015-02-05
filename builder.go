package main

import (
	"flag"
	"net/http"
	"os"
	"strings"

	"github.com/buth/longshore/builder"
)

// containment
var Config struct {
	Path, RegistryPrefix, Users, SlackURL string
}

func init() {
	flag.StringVar(&Config.Path, "p", "/tmp", "root path for git caches")
	flag.StringVar(&Config.RegistryPrefix, "r", "", "registry prefix")
	flag.StringVar(&Config.Users, "u", "", "users")
	flag.StringVar(&Config.SlackURL, "s", os.Getenv(`SLACK_URL`), "slack URL")
}

func main() {
	flag.Parse()
	panic(http.ListenAndServe(":8080", builder.NewBuilder(Config.Path, Config.RegistryPrefix, strings.Split(Config.Users, ","), Config.SlackURL)))
}
