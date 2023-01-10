package spdx22json

import (
	"fmt"
	"io"

	"github.com/spdx/tools-golang/jsonloader"

	"github.com/vela-security/vela-sbom/detect/sbom"
	"github.com/vela-security/vela-sbom/internal/formats/common/spdxhelpers"
)

func decoder(reader io.Reader) (s *sbom.SBOM, err error) {
	defer func() {
		// The spdx tools JSON parser panics in quite a lot of situations, just handle this as a parse failure
		if v := recover(); v != nil {
			s = nil
			err = fmt.Errorf("an error occurred during SPDX JSON document parsing: %+v", v)
		}
	}()

	doc, err := jsonloader.Load2_2(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to decode spdx-json: %w", err)
	}

	return spdxhelpers.ToSyftModel(doc)
}
