package syftjson

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/vela-security/vela-sbom/detect/sbom"

	"github.com/vela-security/vela-sbom/internal/formats/syftjson/model"
)

func decoder(reader io.Reader) (*sbom.SBOM, error) {
	dec := json.NewDecoder(reader)

	var doc model.Document
	err := dec.Decode(&doc)
	if err != nil {
		return nil, fmt.Errorf("unable to decode syft-json: %w", err)
	}

	return toSyftModel(doc)
}
