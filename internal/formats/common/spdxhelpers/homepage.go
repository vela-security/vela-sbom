package spdxhelpers

import "github.com/vela-security/vela-sbom/detect/pkg"

func Homepage(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.GemMetadata:
			return metadata.Homepage
		case pkg.NpmPackageJSONMetadata:
			return metadata.Homepage
		}
	}
	return ""
}
