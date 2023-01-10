package sbom

import "github.com/vela-security/vela-sbom/detect/pkg"

func MetaDataSha1(p pkg.Package) string {
	mt, ok := p.Metadata.(interface{ SHA1() string })
	if ok {
		return mt.SHA1()
	}

	return ""
}
