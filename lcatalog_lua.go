package sbom

import (
	audit "github.com/vela-security/vela-audit"
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	vtime "github.com/vela-security/vela-time"
)

func (lc *LCatalog) String() string                         { return lua.B2S(lc.Byte()) }
func (lc *LCatalog) Type() lua.LValueType                   { return lua.LTObject }
func (lc *LCatalog) AssertFloat64() (float64, bool)         { return 0, false }
func (lc *LCatalog) AssertString() (string, bool)           { return "", false }
func (lc *LCatalog) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (lc *LCatalog) Peek() lua.LValue                       { return lc }

func (lc *LCatalog) pipeL(L *lua.LState) int {
	cnd := cond.New(L.IsString(1))
	pip := pipe.NewByLua(L, pipe.Env(xEnv), pipe.Seek(1))
	n := len(lc.Packages)
	if n == 0 {
		return 0
	}

	for i := 0; i < n; i++ {
		p := lc.Packages[i]
		if cnd.Match(&p) {
			pip.Do(&p, L, func(err error) {
				audit.Errorf("%s sbom catalog pipe call fail %v", lc.Filename, err)
			})
		}
	}
	return 0
}

func (lc *LCatalog) deleteL(L *lua.LState) int {
	n := len(lc.Packages)
	if n == 0 {
		return 0
	}

	name := L.CheckString(1)
	version := L.IsString(2)

	var result []Package
	for i := 0; i < n; i++ {
		pkg := lc.Packages[i]
		if pkg.Name == name && pkg.Version == version {
			continue
		}
		result = append(result, pkg)
	}
	lc.Packages = result
	return 0
}

func (lc *LCatalog) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "filename":
		return lua.S2L(lc.Filename)
	case "checksum":
		return lua.S2L(lc.Checksum)
	case "algorithm":
		return lua.S2L(lc.Algorithm)
	case "mtime":
		return vtime.VTime(lc.MTime)
	case "size":
		return lua.LNumber(lc.Size)
	case "pkg_size":
		return lua.LInt(len(lc.Packages))
	case "delete":
		return lua.NewFunction(lc.deleteL)
	case "pipe":
		return lua.NewFunction(lc.pipeL)
	case "reset":
		return lua.NewFunction(lc.reset)
	}

	return lua.LNil
}
