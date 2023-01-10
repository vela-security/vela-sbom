package sbom

import (
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	vswitch "github.com/vela-security/vela-switch"
	"go.uber.org/ratelimit"
)

const MinFileSize = 1024 * 1024 * 5

type config struct {
	name          string
	limit         ratelimit.Limiter
	remote        bool
	report        bool
	cache         bool
	bucket        []string //扫描记录
	storage       []string //延时扫描存储
	timeout       int
	ignore        *cond.Ignore
	filter        *cond.Combine
	filterCatalog *cond.Combine
	vsh           *vswitch.Switch
	pipe          *pipe.Px
	co            *lua.LState
}

func newConfig(L *lua.LState) *config {
	tab := L.CheckTable(1)
	cfg := &config{
		co:            xEnv.Clone(L),
		vsh:           vswitch.NewL(L),
		ignore:        cond.NewIgnore(),
		filter:        cond.NewCombine(),
		filterCatalog: cond.NewCombine(),
		pipe:          pipe.New(pipe.Env(xEnv)),
		bucket:        []string{"vela", "sbom", "catalog"},
		storage:       []string{"vela", "sbom_file", "storage"},
	}

	tab.Range(func(key string, val lua.LValue) { cfg.NewIndex(L, key, val) })
	return cfg
}

func (cfg *config) NewIndex(L *lua.LState, key string, val lua.LValue) {
	switch key {
	case "name":
		cfg.name = auxlib.CheckProcName(val, L)
	case "remote":
		cfg.remote = lua.IsTrue(val)
	case "report":
		cfg.report = lua.IsTrue(val)
	case "cache":
		cfg.cache = lua.IsTrue(val)
	case "timeout":
		cfg.timeout = lua.IsInt(val)
	case "bucket":
		cfg.bucket = []string{auxlib.CheckProcName(val, L)}
	}
}
