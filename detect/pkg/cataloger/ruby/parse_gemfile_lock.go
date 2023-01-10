package ruby

import (
	"bufio"
	"io"
	"strings"

	"github.com/vela-security/vela-sbom/detect/artifact"
	"github.com/vela-security/vela-sbom/detect/pkg"
	"github.com/vela-security/vela-sbom/detect/pkg/cataloger/common"
	"github.com/vela-security/vela-sbom/internal"
)

// integrity check
var _ common.ParserFn = parseGemFileLockEntries

var sectionsOfInterest = internal.NewStringSet("GEM")

// parseGemFileLockEntries is a parser function for Gemfile.lock contents, returning all Gems discovered.
func parseGemFileLockEntries(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	pkgs := make([]*pkg.Package, 0)
	scanner := bufio.NewScanner(reader)

	var currentSection string

	for scanner.Scan() {
		line := scanner.Text()
		sanitizedLine := strings.TrimSpace(line)

		if len(line) > 1 && line[0] != ' ' {
			// start of section
			currentSection = sanitizedLine
			continue
		} else if !sectionsOfInterest.Contains(currentSection) {
			// skip this line, we're in the wrong section
			continue
		}

		if isDependencyLine(line) {
			candidate := strings.Fields(sanitizedLine)
			if len(candidate) != 2 {
				continue
			}
			pkgs = append(pkgs, &pkg.Package{
				Name:     candidate[0],
				Version:  strings.Trim(candidate[1], "()"),
				Language: pkg.Ruby,
				Type:     pkg.GemPkg,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return pkgs, nil, nil
}

func isDependencyLine(line string) bool {
	if len(line) < 5 {
		return false
	}
	return strings.Count(line[:5], " ") == 4
}
