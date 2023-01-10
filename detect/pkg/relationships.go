package pkg

import "github.com/vela-security/vela-sbom/detect/artifact"

// TODO: as more relationships are added, this function signature will probably accommodate selection
func NewRelationships(catalog *Catalog) []artifact.Relationship {
	return RelationshipsByFileOwnership(catalog)
}
