package sbom

import (
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/vela-security/vela-sbom/detect/pkg/cataloger"
	"os"
)

type Anchore struct {
	Host                   string
	Path                   string
	Username               string
	Password               string
	Dockerfile             string
	OverwriteExistingImage bool
	ImportTimeout          uint
}

type Option struct {
	Filename   string
	Hash       string
	Info       os.FileInfo
	Platform   string
	Registry   image.RegistryOptions
	Exclusions []string
	Anchore    Anchore
	Cataloger  cataloger.Config
}

func Default(filename string) *Option {
	return &Option{
		Filename:  filename,
		Cataloger: cataloger.DefaultConfig(),
	}
}
