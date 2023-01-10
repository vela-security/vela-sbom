package sbom

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	audit "github.com/vela-security/vela-audit"
	opcode "github.com/vela-security/vela-opcode"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-sbom/detect/artifact"
	"github.com/vela-security/vela-sbom/detect/pkg"
	"github.com/vela-security/vela-sbom/detect/sbom"
	"github.com/vela-security/vela-sbom/internal/formats/cyclonedxjson"
	"github.com/vela-security/vela-sbom/internal/formats/spdx22json"
	"os"
	"path/filepath"
	"time"
)

type ExProcData struct {
	Pid      int    `json:"pid"'`
	Exe      string `json:"exe"`
	UserName string `json:"username"`
	Action   string `json:"action"`
	Args     string `json:"args"`
}

type LSbom struct {
	err     error
	ov      *Option
	value   *sbom.SBOM
	timeout time.Duration
	bkt     string
	report  bool
	exData  ExProcData
}

var (
	Null = []byte("")
)

func (lsb *LSbom) Scan() {
	s, e := Scan(lsb.ov)
	lsb.err = e
	lsb.value = s
	if !lsb.report {
		return
	}

	if err := xEnv.TnlSend(opcode.OpSbom, lsb.ToLCatalog()); err != nil {
		audit.Errorf("%s sbom report fail %v", lsb.ov.Filename, err)
		return
	}

	xEnv.Debugf("%s sbom report succeed", lsb.ov.Filename)
}

func (lsb *LSbom) ok() bool {
	return lsb.err == nil
}

func (lsb *LSbom) abs() {
	path, err := filepath.Abs(lsb.ov.Filename)
	if err != nil {
		lsb.err = err
		return
	}
	lsb.ov.Filename = path
}

func (lsb *LSbom) WithCancel() (context.Context, context.CancelFunc) {
	if lsb.timeout > 0 {
		return context.WithTimeout(context.Background(), lsb.timeout)
	}

	return context.WithCancel(context.Background())
}

func (lsb *LSbom) sha1() {
	fd, err := os.Open(lsb.ov.Filename)
	if err != nil {
		lsb.err = err
		return
	}
	defer fd.Close()

	info, err := fd.Stat()
	if err != nil {
		lsb.err = err
		return
	}

	if info.IsDir() {
		lsb.err = fmt.Errorf("%s is dir", lsb.ov.Filename)
		return
	}

	ctx, stop := lsb.WithCancel()
	defer stop()
	sh1 := sha1.New()
	auxlib.Copy(ctx, sh1, fd)
	hash := fmt.Sprintf("%x", sh1.Sum(nil))

	lsb.ov.Hash = hash
	lsb.ov.Info = info
}

func (lsb *LSbom) spdx() []byte {
	if !lsb.ok() {
		return []byte("")
	}

	var buffer bytes.Buffer
	err := spdx22json.Format().Encode(&buffer, *lsb.value)
	if err != nil {
		xEnv.Errorf("%s spdx json fail %v", lsb.ov.Filename, err)
		return []byte("")
	}

	return buffer.Bytes()
}

func (lsb *LSbom) cyclonedx() []byte {
	if !lsb.ok() {
		return Null
	}

	var buffer bytes.Buffer
	err := cyclonedxjson.Format().Encode(&buffer, *lsb.value)
	if err != nil {
		xEnv.Errorf("%s spdx json fail %v", lsb.ov.Filename, err)
		return []byte("")
	}

	return buffer.Bytes()
}

func (lsb *LSbom) reportSpdx() error {
	chunk := lsb.spdx()
	n := len(chunk)
	if n == 0 {
		return fmt.Errorf("not found %s spdx value", lsb.ov.Filename)
	} else {
		chunk[n-2] = ','
	}

	enc := kind.NewJsonEncoder()
	enc.Tab("checksum")
	enc.KV("algorithm", "SHA1")
	enc.KV("checksumValue", lsb.ov.Hash)
	enc.End("}}")
	chunk = append(chunk, enc.Bytes()...)

	if e := xEnv.TnlSend(opcode.OpSpdx, json.RawMessage(chunk)); e != nil {
		return e
	}

	return nil
}

func (lsb *LSbom) reportCyclonedx() error {
	return nil
}

func (lsb *LSbom) Byte() []byte {
	chunk, err := json.Marshal(lsb.value)
	if err != nil {
		xEnv.Errorf("sbom marshal fail %v", err)
		return nil
	}
	return chunk
}

func (lsb *LSbom) LookupCatalog(bkt assert.Bucket) *LCatalog {
	lc := LCatalog{Checksum: lsb.ov.Hash, Filename: lsb.ov.Filename}

	data, err := bkt.Value(lc.Checksum)
	if err != nil {
		xEnv.Debugf("file:%s sha1:s sbom catalog not found", lc.Filename, lc.Checksum)
		return nil
	}

	err = json.Unmarshal(data, &lc)
	if err != nil {
		audit.Errorf("file:%s hash:%s sbom catalog cache decode json fail %v",
			lc.Checksum, lc.Filename, err).From("inline").Log().Put()
		return nil
	}

	return &lc
}

func (lsb *LSbom) ToLCatalog() *LCatalog {
	if !lsb.ok() {
		return nil
	}

	n := lsb.value.Artifacts.PackageCatalog.PackageCount()
	r := &LCatalog{
		Filename:  lsb.ov.Filename,
		Algorithm: "SHA1",
		Checksum:  lsb.ov.Hash,
		MTime:     lsb.ov.Info.ModTime(),
		Size:      lsb.ov.Info.Size(),
		Packages:  make([]Package, 0, n),
		ExData:    lsb.exData,
	}

	lsb.value.Artifacts.PackageCatalog.Visit(func(id artifact.ID, p pkg.Package) {
		r.append(Package{
			PackageURL: p.PURL,
			Version:    p.Version,
			Name:       p.Name,
			Language:   string(p.Language),
			Licenses:   p.Licenses,
			Algorithm:  "SHA1",
			Checksum:   MetaDataSha1(p),
		})
	})

	return r
}

func (lsb *LSbom) WithTimeout(v int) {
	if v == 0 {
		return
	}

	lsb.timeout = time.Duration(v) * time.Millisecond
}

func newLSbom(filename string, report bool) *LSbom {
	lsb := &LSbom{
		ov:     Default(filename),
		report: report,
	}

	lsb.abs()
	return lsb
}
