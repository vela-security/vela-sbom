package spdx

import "encoding/json"

func Decode(chunk []byte) (*Spdx, error) {
	sdx := Spdx{}
	err := json.Unmarshal(chunk, &sdx)
	return &sdx, err
}
