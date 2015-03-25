package github

import (
	"strings"
)

type Payload struct {
	Ref     string `json:"ref"`
	Before  string `json:"before"`
	After   string `json:"after"`
	Compare string `json:"compare"`
	Pusher  *User  `json:"pusher"`

	HeadCommit struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		URL     string `json:"url"`
		Author  *User  `json:"author"`
	} `json:"head_commit"`

	Repository struct {
		Owner       *User  `json:"owner"`
		Name        string `json:"name"`
		FullName    string `json:"full_name"`
		URL         string `json:"url"`
		SSHURL      string `json:"ssh_url"`
		Description string `json:"description"`
	} `json:"repository"`
}

func (p Payload) Branch() string {
	if strings.HasPrefix(p.Ref, "refs/heads/") {
		return strings.TrimPrefix(p.Ref, "refs/heads/")
	}
	return ""
}
