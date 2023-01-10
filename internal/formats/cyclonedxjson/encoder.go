package cyclonedxjson

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/vela-security/vela-sbom/detect/sbom"
	"github.com/vela-security/vela-sbom/internal/formats/common/cyclonedxhelpers"
)

func encoder(output io.Writer, s sbom.SBOM) error {
	bom := cyclonedxhelpers.ToFormatModel(s)
	enc := cyclonedx.NewBOMEncoder(output, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)

	err := enc.Encode(bom)
	return err
}
