package cyclonedxjson

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/vela-security/vela-sbom/detect/sbom"
	"github.com/vela-security/vela-sbom/internal/formats/common/cyclonedxhelpers"
)

const ID sbom.FormatID = "cyclonedx-1-json"

func Format() sbom.Format {
	return sbom.NewFormat(
		ID,
		encoder,
		cyclonedxhelpers.GetDecoder(cyclonedx.BOMFileFormatJSON),
		cyclonedxhelpers.GetValidator(cyclonedx.BOMFileFormatJSON),
	)
}
