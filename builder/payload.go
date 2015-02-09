package builder

import (
	"fmt"
	"strings"
)

type User struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

type Repository struct {
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	Owner       User   `json:"owner"`
	SSHURL      string `json:"ssh_url"`
	HTMLURL     string `json:"html_url"`
	Description string `json:"description"`
}

type Payload struct {
	Ref        string `json:"ref"`
	HeadCommit struct {
		ID        string `json:"id"`
		Message   string `json:"message"`
		Committer User   `json:"committer"`
		URL       string `json:"url"`
	} `json:"head_commit"`
	Repository Repository `json:"repository"`
	Pusher     User       `json:"pusher"`
}

func (p Payload) Branch() string {
	if strings.HasPrefix(p.Ref, "refs/heads/") {
		return strings.TrimPrefix(p.Ref, "refs/heads/")
	}
	return ""
}

func (p Payload) Tag() string {
	branch := p.Branch()
	switch branch {
	case "master":
		return "latest"
	case "develop":
		return "staging"
	default:
		return branch
	}
}

func (p Payload) Attatchment() *Attatchment {

	commit := p.HeadCommit.ID[len(p.HeadCommit.ID)-10:]

	a := NewAttatchment()
	a.Title = fmt.Sprintf("github.com/%s", p.Repository.FullName)
	a.TitleLink = p.Repository.HTMLURL
	a.Text = p.Repository.Description
	a.AuthorIcon = "https://nytnews.slack.com/emoji/github/9382f523e571772d.png"
	a.AuthorName = "GitHub"
	a.Fields = []*Field{
		&Field{
			Title: "Git Branch",
			Value: p.Branch(),
			Short: true,
		},
		&Field{
			Title: "Git Commit",
			Value: fmt.Sprintf("<%s|%s>", p.HeadCommit.URL, commit),
			Short: true,
		},
	}

	return a
}
