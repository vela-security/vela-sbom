package table

import (
	"github.com/vela-security/vela-sbom/detect/sbom"
)

const ID sbom.FormatID = "syft-table"

func Format() sbom.Format {
	return sbom.NewFormat(
		ID,
		encoder,
		nil,
		nil,
	)
}
