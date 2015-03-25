package builder

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

type Field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type Attatchment struct {
	Fallback   string   `json:"fallback"`
	Color      string   `json:"color"`
	Pretext    string   `json:"pretext"`
	AuthorName string   `json:"author_name"`
	AuthorIcon string   `json:"author_icon"`
	Title      string   `json:"title"`
	TitleLink  string   `json:"title_link"`
	Text       string   `json:"text"`
	MarkdownIn []string `json:"mrkdwn_in"`
	Fields     []*Field `json:"fields"`
}

func NewAttatchment() *Attatchment {
	return &Attatchment{
		Fields: make([]*Field, 0),
	}
}

type Message struct {
	Text         string         `json:"text"`
	Attatchments []*Attatchment `json:"attachments"`
}

func NewMessage() *Message {
	return &Message{
		Attatchments: make([]*Attatchment, 0),
	}
}

func (m *Message) Attatch(attatchment *Attatchment) {
	m.Attatchments = append(m.Attatchments, attatchment)
}

func (m *Message) Send(slackURL string) error {

	payloadJson, err := json.Marshal(m)
	if err != nil {
		return err
	}

	response, err := http.PostForm(slackURL, url.Values{"parse": {"none"}, "payload": {string(payloadJson)}})
	if err != nil {
		return err
	}

	if response.StatusCode >= 400 {
		return errors.New("couldn't message Slack")
	}

	return nil
}
