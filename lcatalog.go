package sbom

import (
	"encoding/json"
	audit "github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
	"time"
)

type LCatalog struct {
	Filename  string     `json:"filename"`
	Checksum  string     `json:"checksum"`
	Algorithm string     `json:"algorithm"`
	Packages  []Package  `json:"packages"`
	MTime     time.Time  `json:"modify_time"`
	Size      int64      `json:"size"`
	ExData    ExProcData `json:"process"`
}

func (lc *LCatalog) store(bkt assert.Bucket) {
	err := bkt.Push(lc.Checksum, lc.Byte(), 0)
	if err != nil {
		audit.Errorf("%s sbom catalog store fail %v", lc.Filename, err).From("inline").Log().Put()
	}
}

func (lc *LCatalog) find(bkt assert.Bucket) {
	data, err := bkt.Value(lc.Checksum)
	if err != nil {
		xEnv.Debugf("file:%s sha1:s sbom catalog not found", lc.Filename, lc.Checksum)
		return
	}

	err = json.Unmarshal(data, lc)
	if err != nil {
		audit.Errorf("file:%s hash:%s sbom catalog cache decode json fail %v",
			lc.Checksum, lc.Filename, err).From("inline").Log().Put()
	}
}

func (lc *LCatalog) append(p Package) {
	lc.Packages = append(lc.Packages, p)
}

func (lc *LCatalog) deleteByIndex(i int) {
}

func (lc *LCatalog) Byte() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("filename", lc.Filename)
	enc.KV("checksum", lc.Checksum)
	enc.KV("algorithm", lc.Algorithm)
	enc.KV("modify_time", lc.MTime)
	enc.KV("size", lc.Size)
	enc.Arr("packages")
	for _, p := range lc.Packages {
		enc.Append(p.Byte())
	}
	enc.End("]}")
	return enc.Bytes()
}

func (lc *LCatalog) reset(L *lua.LState) int {
	lc.Packages = nil
	return 0
}
