package cyclonedx

import "encoding/json"

func Decode(chunk []byte) (*Cyclonedx, error) {
	cdx := Cyclonedx{}
	err := json.Unmarshal(chunk, &cdx)
	return &cdx, err
}
