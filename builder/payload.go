package builder

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
)

type User struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

type Repository struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Owner    User   `json:"owner"`
	SSHURL   string `json:"ssh_url"`
	URL      string `json:"url"`
}

type Payload struct {
	Ref        string `json:"ref"`
	HeadCommit struct {
		ID        string `json:"id"`
		Message   string `json:"message"`
		Committer User   `json:"committer"`
	} `json:"head_commit"`
	Repository Repository `json:"repository"`
	Pusher     User       `json:"pusher"`
}

func (p Payload) Log(key string) io.Writer {

	prefix := fmt.Sprintf(
		"%s:%s %s %s",
		p.Repository.FullName,
		strings.TrimPrefix(p.Ref, `refs/`),
		p.HeadCommit.ID[len(p.HeadCommit.ID)-10:],
		key,
	)

	buf := bytes.NewBuffer([]byte{})

	go func() {

		scanner := bufio.NewScanner(buf)
		for scanner.Scan() {
			log.Printf("%s: %s", prefix, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Printf("%s: %s", prefix, err.Error())
		}

	}()

	return buf
}
