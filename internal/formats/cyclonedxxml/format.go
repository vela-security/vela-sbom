package cyclonedxxml

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/vela-security/vela-sbom/detect/sbom"
	"github.com/vela-security/vela-sbom/internal/formats/common/cyclonedxhelpers"
)

const ID sbom.FormatID = "cyclonedx-1-xml"

func Format() sbom.Format {
	return sbom.NewFormat(
		ID,
		encoder,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatXML),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatXML),
	)
}
