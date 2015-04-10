package builder

import (
	"encoding/json"
	"io"

	"github.com/newsdev/longshore/vendor/src/github.com/go-mgo/mgo"
	"github.com/newsdev/longshore/vendor/src/github.com/go-mgo/mgo/bson"
)

func writeBson(data *bson.M, w io.Writer) error {

	// Encode the data as json.
	resultBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	if _, err := w.Write(resultBytes); err != nil {
		return err
	}

	return nil
}

func writeResult(result interface{}, w io.Writer) error {
	return writeBson(&bson.M{
		"result": result,
	}, w)
}

func writeAllAsResult(iter *mgo.Iter, w io.Writer) error {

	var result []*bson.M
	if err := iter.All(&result); err != nil {
		return err
	}

	return writeResult(result, w)
}
