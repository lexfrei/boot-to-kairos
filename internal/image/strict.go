package image

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"io"

	"github.com/cockroachdb/errors"
)

// ErrInvalidJSON is image metadata that JSON parsers may read differently:
// an object that names a member twice, invalid UTF-8, or data after the
// value.
var ErrInvalidJSON = errors.New("not strict JSON")

// StrictJSON refuses raw if encoding/json reads it but a strict parser
// would not: go-containerregistry, like encoding/json, keeps the last of
// two members, replaces invalid UTF-8 and stops after the first value, so
// bytes whose digest matches may still mean one thing here and another to
// a registry, cosign or jq. What encoding/json cannot read at all is left
// to the parser that follows.
func StrictJSON(raw []byte) error {
	var first json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&first); err != nil {
		return nil //nolint:nilerr // the parser that follows refuses it too
	}
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.ReadValue(); err != nil {
		return errors.Wrap(ErrInvalidJSON, err.Error())
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		return errors.Wrap(ErrInvalidJSON, "data after the JSON value")
	}
	return nil
}
