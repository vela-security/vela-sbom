package sbom

import (
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
	"strings"
)

type Package struct {
	PackageURL string   `json:"purl"`
	Version    string   `json:"version"`
	Name       string   `json:"name"`
	Algorithm  string   `json:"algorithm"`
	Checksum   string   `json:"checksum"`
	Licenses   []string `json:"licenses"`
	Language   string   `json:"language"`
}

func (p *Package) Byte() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("purl", p.PackageURL)
	enc.KV("name", p.Name)
	enc.KV("version", p.Version)
	enc.KV("algorithm", p.Algorithm)
	enc.KV("checksum", p.Checksum)
	enc.KV("licenses", strings.Join(p.Licenses, ","))
	enc.KV("language", p.Language)
	enc.End("}")
	return enc.Bytes()
}

func (p *Package) String() string                         { return lua.B2S(p.Byte()) }
func (p *Package) Type() lua.LValueType                   { return lua.LTObject }
func (p *Package) AssertFloat64() (float64, bool)         { return 0, false }
func (p *Package) AssertString() (string, bool)           { return "", false }
func (p *Package) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (p *Package) Peek() lua.LValue                       { return p }

func (p *Package) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "purl":
		return lua.S2L(p.PackageURL)
	case "version":
		return lua.S2L(p.Version)
	case "name":
		return lua.S2L(p.Name)
	case "algorithm":
		return lua.S2L(p.Algorithm)
	case "checksum":
		return lua.S2L(p.Checksum)
	case "licenses":
		return lua.S2L(strings.Join(p.Licenses, ","))
	case "language":
		return lua.S2L(p.Language)

	}
	return lua.LNil
}
