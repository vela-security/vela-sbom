package spdx22tagvalue

import (
	"io"

	"github.com/spdx/tools-golang/tvsaver"
	"github.com/vela-security/vela-sbom/detect/sbom"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	model := toFormatModel(s)
	return tvsaver.Save2_2(model, output)
}
