package utils

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

// Secret contains data and metadata related to a scuttle-managed secret.
//
// An example JSON-serialized secret:
//
//    {
//      "name": "A_SECRET",
//      "cypher": "0xD34DB33F",
//      "created": "2019-05-01 13:01:27.189242799 -0500 CDT m=+0.000075907",
//      "encoding": "plain"
//     }
type Secret struct {
	Name       string    `json:"name"`
	Cyphertext string    `json:"cypher"`
	Created    time.Time `json:"created"`
	Encoding   string    `json:"encoding"`
}

// Secrets - A collection of Secret
type Secrets []Secret

// Remove -  a secret from the collection
func (s *Secrets) Remove(name string) {
	for index, element := range *s {
		if element.Name == name {
			log.Printf("Removing entry %s", element.Name)
			*s = append((*s)[:index], (*s)[index+1:]...)
		}
	}
}

// Add - Upsert a secret into the collection. If a key exists,
// it will presume rotation, and update in-place.
func (s *Secrets) Add(toAdd Secret) {
	// Adds or Updates a secret
	for index, element := range *s {
		if element.Name == toAdd.Name {
			log.Printf("Rotating entry %s", element.Name)
			*s = append((*s)[:index], (*s)[index+1:]...)
		}
	}
	*s = append((*s), toAdd)
}

// V2 Secrets is a representation of the envelope enhanced to track their
// own key URI.
// This secret wrapper will validate that an incoming request to encrypt
// matches the same key declared on the state file before performing IO.
// otherwise it raises an error.
type V2 struct {
	KeyIdentifier string `json:"key_uri"`
	Version       string `json:"version"`
	Filepath      string `json:"-"`
	Secrets       `json:"secrets"`
}

// SameKey compares the KeyURI for the incoming encrypt/decrypt request.
// Returns false if the key URI's do not match
func (s *V2) SameKey(key string) bool {
	// short circuit the first run schenanigans and attempt to return this
	// right away if we have any secrets in the struct
	if len(s.Secrets) > 0 && len(s.KeyIdentifier) == 0 && len(key) > 0 {
		log.Debug("No KeyURI found in envelope. Presuming current key is the correct key.")
		return true
	}

	// Things can get dicey on first run, as there's no keyfile identifier,
	// so we have to assume yes as this function will gate writes.
	if len(s.KeyIdentifier) == 0 && len(s.Secrets) == 0 {
		log.WithFields(log.Fields{
			"KeyIdentifier": s.KeyIdentifier,
			"Secrets":       s.Secrets,
		}).Debug("Checking first run conditions")
		return true
	}

	return s.KeyIdentifier == key
}

// GetVersion returns the statically declared version for the type of SecretsV2 - "2"
func (s V2) GetVersion() string {
	return "2"
}

// Load ...
func (s *V2) Load() error {
	file, err := ioutil.ReadFile(s.Filepath)
	if err != nil {
		if os.IsNotExist(err) {
			// The file doesn't exist, dont raise an error and return empty data to account
			// for first-run without a state serialized to disk.
			s.Version = s.GetVersion()
			return nil
		}
		return err
	}

	// Decode the json into a V2 Secret
	return json.Unmarshal([]byte(file), s)
}

// Save ...
func (s *V2) Save() error {
	if s.Version == "" {
		s.Version = "2"
	}
	if len(s.KeyIdentifier) == 0 {
		log.Warn("No KeyURI provided to scuttles envelope. Saving without KeyIndicator embedded.")
	}
	jsonData, _ := json.MarshalIndent(s, "", " ")
	mode := int(0660) // file mode
	return ioutil.WriteFile(s.Filepath, jsonData, os.FileMode(mode))
}
