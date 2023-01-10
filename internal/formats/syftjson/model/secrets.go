package model

import (
	"github.com/vela-security/vela-sbom/detect/file"
	"github.com/vela-security/vela-sbom/detect/source"
)

type Secrets struct {
	Location source.Coordinates  `json:"location"`
	Secrets  []file.SearchResult `json:"secrets"`
}
