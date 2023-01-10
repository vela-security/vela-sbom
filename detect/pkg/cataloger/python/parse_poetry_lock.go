package python

import (
	"fmt"
	"github.com/pelletier/go-toml"
	"io"

	"github.com/vela-security/vela-sbom/detect/artifact"
	"github.com/vela-security/vela-sbom/detect/pkg"
	"github.com/vela-security/vela-sbom/detect/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parsePoetryLock

// parsePoetryLock is a parser function for poetry.lock contents, returning all python packages discovered.
func parsePoetryLock(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	tree, err := toml.LoadReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load poetry.lock for parsing: %v", err)
	}

	metadata := PoetryMetadata{}
	err = tree.Unmarshal(&metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse poetry.lock: %v", err)
	}

	return metadata.Pkgs(), nil, nil
}
