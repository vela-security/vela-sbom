/*
Package php provides a concrete Cataloger implementation for PHP ecosystem files.
*/
package php

import (
	"github.com/vela-security/vela-sbom/detect/pkg/cataloger/common"
)

// NewPHPComposerInstalledCataloger returns a new cataloger for PHP installed.json files.
func NewPHPComposerInstalledCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/installed.json": parseInstalledJSON,
	}

	return common.NewGenericCataloger(nil, globParsers, "php-composer-installed-cataloger")
}

// NewPHPComposerLockCataloger returns a new cataloger for PHP composer.lock files.
func NewPHPComposerLockCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/composer.lock": parseComposerLock,
	}

	return common.NewGenericCataloger(nil, globParsers, "php-composer-lock-cataloger")
}
