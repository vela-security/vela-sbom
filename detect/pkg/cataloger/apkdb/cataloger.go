/*
Package apkdb provides a concrete Cataloger implementation for Alpine DB files.
*/
package apkdb

import (
	"github.com/vela-security/vela-sbom/detect/pkg"
	"github.com/vela-security/vela-sbom/detect/pkg/cataloger/common"
)

// NewApkdbCataloger returns a new Alpine DB cataloger object.
func NewApkdbCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		pkg.ApkDBGlob: parseApkDB,
	}

	return common.NewGenericCataloger(nil, globParsers, "apkdb-cataloger")
}
