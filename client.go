package sbom

import (
	"encoding/json"
	"fmt"
	audit "github.com/vela-security/vela-audit"
	file "github.com/vela-security/vela-file"
	opcode "github.com/vela-security/vela-opcode"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
	"gopkg.in/tomb.v2"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type handle func(string, ExProcData) error

type client struct {
	lua.ProcEx
	cfg  *config
	bkt  assert.Bucket
	tomb *tomb.Tomb
}

func (cli *client) wait() {
	if cli.cfg.limit == nil {
		return
	}
	cli.cfg.limit.Take()
}

func (cli *client) filter(filename string) bool {
	stat, err := os.Stat(filename)
	if err != nil {
		xEnv.Infof("%s sbom client not found %s", cli.Name(), filename)
		return false
	}

	if stat.IsDir() {
		return false
	}

	if stat.Size() < 30 {
		return false
	}

	if cli.cfg.filter == nil {
		return true
	}

	info := file.NewLInfo(filename, stat, nil)
	return cli.cfg.filter.Match(info)
}

func (cli *client) Report(lc *LCatalog) {
	if !cli.cfg.report {
		xEnv.Debugf("%s report catalog off", cli.Name())
		return
	}

	if e := xEnv.TnlSend(opcode.OpSbom, lc); e != nil {
		xEnv.Errorf("%s report catalog fail %v", cli.Name(), e)
	}
}

func (cli *client) filterByCatalog(lc *LCatalog) bool {
	if cli.cfg.filterCatalog == nil {
		return true

	}
	return cli.cfg.filterCatalog.Match(lc)
}

func (cli *client) Do(file string, exData ExProcData) error {
	if !cli.IsRun() {
		return fmt.Errorf("%s sbom client not running", cli.Name())
	}

	lc, err := cli.scan(file, exData)
	if err != nil {
		audit.Errorf("%s sbom client scan %s error %#v", cli.Name(), file, err, exData).
			From(cli.cfg.co.CodeVM()).Put()

		return err
	}

	if lc == nil {
		return nil
	}

	if !cli.filterByCatalog(lc) {
		return nil
	}

	cli.Report(lc)

	cli.cfg.vsh.Do(lc)

	cli.cfg.pipe.Do(lc, cli.cfg.co, func(err error) {
		audit.Errorf("%s %s sbom pipe call fail %v", cli.cfg.name, file).From(cli.cfg.co.CodeVM()).Put()
	})

	audit.Infof("%s sbom client scan %s over %#v", cli.Name(), file, exData).From(cli.cfg.co.CodeVM()).Put()
	return nil
}

func (cli *client) sync(file string, exData ExProcData) error {
	if !cli.IsRun() {
		return fmt.Errorf("%s sbom client not running", cli.Name())
	}
	xEnv.Spawn(0, func() { cli.Do(file, exData) })
	return nil
}

func (cli *client) push(file string, data ExProcData) error {
	filename, err := filepath.Abs(file)
	if err != nil {
		xEnv.Infof("%s sbom client push file error %v", cli.Name(), err)
		return err
	}

	if cli.cfg.ignore.Match(filename) {
		return nil
	}

	if !cli.filter(filename) {
		return nil
	}

	key := fmt.Sprintf("%d_%s", time.Now().Unix(), filename)
	bkt := xEnv.Bucket(cli.cfg.storage...)

	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("pid", data.Pid)
	enc.KV("exe", data.Exe)
	enc.KV("username", data.UserName)
	enc.End("}")
	return bkt.Push(key, enc.Bytes(), 0)
}

func (cli *client) task(clear bool) {
	bkt := xEnv.Bucket(cli.cfg.storage...)
	bkt.ForEach(func(key string, data []byte) {
		var exData ExProcData
		err := json.Unmarshal(data, &exData)
		if err != nil {
			audit.Errorf("%s sbom client delay task got fail file:%s data:%s",
				cli.Name(), key, data).From(cli.cfg.co.CodeVM()).Put()
			return
		}

		idx := strings.IndexByte(key, '_')
		if idx < 0 {
			return
		}
		cli.sync(key[idx+1:], exData)
	})

	if clear {
		bkt.Clear()
		audit.Infof("%s sbom client delay task clear over", cli.Name()).From(cli.cfg.co.CodeVM()).Put()
	}
}

func (cli *client) byCache(lsb *LSbom) *LCatalog {
	//缓存
	if !cli.cfg.cache {
		return nil
	}

	return lsb.LookupCatalog(cli.bkt)
}

func (cli *client) byRemote(lsb *LSbom) *LCatalog {
	//缓存
	if !cli.cfg.cache {
		return nil
	}

	return nil
}

func (cli *client) byScan(lsb *LSbom) (*LCatalog, error) {
	//扫描
	s, e := Scan(lsb.ov)
	if e != nil {
		return nil, e
	}

	if s == nil {
		return nil, nil
	}

	lsb.value = s
	return lsb.ToLCatalog(), nil
}

func (cli *client) scan(file string, exData ExProcData) (*LCatalog, error) {
	//限速
	cli.wait()
	lsb := newLSbom(file, cli.cfg.report)
	if lsb.err != nil {
		return nil, lsb.err
	}
	lsb.exData = exData
	lsb.WithTimeout(cli.cfg.timeout)

	if cli.cfg.ignore.Match(file) {
		return nil, nil
	}

	if !cli.filter(file) {
		return nil, nil
	}

	audit.Infof("%s sbom client init scan %s proc:%#v", cli.Name(), file, exData).From(cli.cfg.co.CodeVM()).Put()

	//提取hash
	lsb.sha1()

	if lc := cli.byCache(lsb); lc != nil {
		return lc, nil
	}

	if lc := cli.byRemote(lsb); lc != nil {
		return lc, nil
	}

	return cli.byScan(lsb)
}

func newClient(cfg *config) *client {
	cli := &client{cfg: cfg}
	return cli
}
