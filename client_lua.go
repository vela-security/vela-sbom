package sbom

import (
	cond "github.com/vela-security/vela-cond"
	process2 "github.com/vela-security/vela-process"
	"github.com/vela-security/vela-public/lua"
	track2 "github.com/vela-security/vela-track"
	"go.uber.org/ratelimit"
	"reflect"
	"time"
)

var typeof = reflect.TypeOf((*client)(nil)).String()

/*
	local cli = vela.sbom.client{
		name = "sbom_scan",
		max = 123456,
		limit = 1,
		report = true,
		bkt = "sbom"
		remote = true,
	}

	cli.by_file("xxx")
	cli.by_pid(123)
	cli.by_pid_track(123)
	cli.by_track("123")
*/

func (cli *client) Start() error {
	cli.bkt = xEnv.Bucket(cli.cfg.bucket...)
	return nil
}

func (cli *client) Close() error {
	xEnv.Free(cli.cfg.co)
	cli.V(lua.PTClose)
	return nil
}

func (cli *client) Name() string {
	return cli.cfg.name
}

func (cli *client) Type() string {
	return typeof
}

func (cli *client) pipeL(L *lua.LState) int {
	cli.cfg.pipe.CheckMany(L)
	return 0
}

func (cli *client) run(L *lua.LState) int {
	xEnv.Start(L, cli).From(L.CodeVM()).Do()
	return 0
}

func (cli *client) Range(L *lua.LState, seek int, fn func(*lua.LState, int)) int {
	n := L.GetTop()
	if n == 0 {
		return 0
	}

	if n < seek {
		return 0
	}

	for idx := seek + 1; idx <= n; idx++ {
		fn(L, idx)
	}

	return 0
}

func (cli *client) file(L *lua.LState, do handle) int {
	return cli.Range(L, 0, func(co *lua.LState, i int) {
		do(co.CheckString(i), ExProcData{})
	})
}

func (cli *client) pid(L *lua.LState, do handle) int {
	return cli.Range(L, 0, func(co *lua.LState, idx int) {
		pid := L.IsInt(idx)
		if pid < 0 {
			return
		}

		p, err := process2.Pid(pid)
		if err != nil {
			xEnv.Errorf("%s sbom client %s pid process not found", cli.Name(), pid)
		}

		if p == nil {
			return
		}

		do(p.Executable, ExProcData{
			Pid:      pid,
			Exe:      p.Executable,
			UserName: p.Username,
		})
	})
}

func (cli *client) pidTrack(L *lua.LState, do handle) int {
	cnd := cond.New(L.IsString(1))
	return cli.Range(L, 1, func(co *lua.LState, idx int) {
		pid := L.IsInt(idx)
		if pid < 0 {
			return
		}
		tk := track2.ByPid(int32(pid), cnd)
		p, err := process2.Pid(pid)
		var exData ExProcData
		if err != nil {
			xEnv.Infof("sbom client got pid %d fail %v", pid, err)
		} else {
			exData.Pid = pid
			exData.Exe = p.Executable
			exData.UserName = p.Username
		}
		tk.Visit(func(s track2.Section) { do(s.Value, exData) })
		tk.Reset()
	})
}

func (cli *client) process(L *lua.LState, do handle) int {
	return cli.Range(L, 0, func(co *lua.LState, idx int) {
		p := process2.CheckById(L, idx)
		if p == nil {
			return
		}
		do(p.Executable, ExProcData{
			Pid:      p.Pid,
			Exe:      p.Executable,
			UserName: p.Username,
		})
	})
}

func (cli *client) processTrack(L *lua.LState, do handle) int {
	cnd := cond.New(L.IsString(1))

	return cli.Range(L, 1, func(co *lua.LState, idx int) {
		p := process2.CheckById(L, idx)
		if p == nil {
			return
		}
		tk := track2.ByProcess(p, cnd)
		tk.Visit(func(s track2.Section) {
			do(s.Value, ExProcData{
				Pid:      int(s.Pid),
				Exe:      s.Exe,
				Args:     p.ArgsToString(),
				UserName: s.User,
			})
		})
		tk.Reset()
	})
}

func (cli *client) track(L *lua.LState, do handle) int {
	cnd := cond.New(L.IsString(1))
	return cli.Range(L, 1, func(co *lua.LState, idx int) {
		tk := track2.ByName(L.CheckString(idx), cnd)
		tk.Visit(func(s track2.Section) {
			do(s.Value, ExProcData{
				Pid:      int(s.Pid),
				Exe:      s.Exe,
				UserName: s.User,
			})
		})
		tk.Reset()
	})
}

func (cli *client) NewLFunc(exec func(*lua.LState, handle) int, fn handle) *lua.LFunction {
	return lua.NewFunction(func(L *lua.LState) int {
		return exec(L, fn)
	})
}

func (cli *client) filterL(L *lua.LState) int {
	cli.cfg.filter.CheckMany(L, cond.WithCo(L))
	return 0
}

func (cli *client) ignoreL(L *lua.LState) int {
	cli.cfg.ignore.CheckMany(L, cond.WithCo(L))
	return 0
}

func (cli *client) filterByCatalogL(L *lua.LState) int {
	cli.cfg.filterCatalog.CheckMany(L)
	return 0
}

func (cli *client) limitL(L *lua.LState) int {
	n := L.IsInt(1)
	p := L.IsInt(2)
	if n <= 0 {
		return 0
	}

	if p <= 0 {
		cli.cfg.limit = ratelimit.New(n)
	} else {
		cli.cfg.limit = ratelimit.New(n, ratelimit.Per(time.Duration(p)*time.Millisecond))
	}

	return 0
}

func (cli *client) taskL(L *lua.LState) int {
	clear := L.IsTrue(1)
	xEnv.Spawn(0, func() {
		cli.task(clear)
	})
	return 0
}

func (cli *client) clearL(L *lua.LState) int {
	bkt := xEnv.Bucket(cli.cfg.storage...)
	bkt.Clear()
	return 0
}

func (cli *client) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "pipe":
		return lua.NewFunction(cli.pipeL)
	case "ignore":
		return lua.NewFunction(cli.ignoreL)
	case "filter":
		return lua.NewFunction(cli.filterL)
	case "case":
		return cli.cfg.vsh.Index(L, "case")

	case "filter_by_catalog":
		return lua.NewFunction(cli.filterByCatalogL)
	case "limit":
		return lua.NewFunction(cli.limitL)
	case "by_file":
		return cli.NewLFunc(cli.file, cli.Do)
	case "by_pid":
		return cli.NewLFunc(cli.pid, cli.Do)
	case "by_pid_track":
		return cli.NewLFunc(cli.pidTrack, cli.Do)
	case "by_process":
		return cli.NewLFunc(cli.process, cli.Do)
	case "by_process_track":
		return cli.NewLFunc(cli.processTrack, cli.Do)
	case "by_track":
		return cli.NewLFunc(cli.track, cli.Do)

	case "sync_by_file":
		return cli.NewLFunc(cli.file, cli.sync)
	case "sync_by_pid":
		return cli.NewLFunc(cli.pid, cli.sync)
	case "sync_by_pid_track":
		return cli.NewLFunc(cli.pidTrack, cli.sync)
	case "sync_by_process":
		return cli.NewLFunc(cli.process, cli.sync)
	case "sync_by_process_track":
		return cli.NewLFunc(cli.processTrack, cli.sync)
	case "sync_by_track":
		return cli.NewLFunc(cli.track, cli.sync)

	case "push_by_file":
		return cli.NewLFunc(cli.file, cli.push)
	case "push_by_pid":
		return cli.NewLFunc(cli.pid, cli.push)
	case "push_by_pid_track":
		return cli.NewLFunc(cli.pidTrack, cli.push)
	case "push_by_process":
		return cli.NewLFunc(cli.process, cli.push)
	case "push_by_process_track":
		return cli.NewLFunc(cli.processTrack, cli.push)
	case "push_by_track":
		return cli.NewLFunc(cli.track, cli.push)

	case "task":
		return lua.NewFunction(cli.taskL)
	case "clear":
		return lua.NewFunction(cli.clearL)

	case "start":
		return lua.NewFunction(cli.run)
	}

	return lua.LNil
}

func CheckClientById(L *lua.LState, idx int) *client {
	pro := L.CheckProcData(idx)
	cli, ok := pro.Data.(*client)
	if ok {
		return cli
	}
	L.RaiseError("invalid sbom client")
	return nil
}

func CheckClientByVal(L *lua.LState, val lua.LValue) *client {
	if val.Type() != lua.LTProcData {
		L.RaiseError("not sbom client proc , got %s", val.Type().String())
		return nil
	}

	cli, ok := val.(*lua.ProcData).Data.(*client)
	if ok {
		return cli
	}
	L.RaiseError("invalid sbom client")
	return nil
}

func newLuaSbomClient(L *lua.LState) int {
	cfg := newConfig(L)
	pro := L.NewProc(cfg.name, typeof)
	if pro.IsNil() {
		pro.Set(newClient(cfg))
	} else {
		cli := pro.Data.(*client)
		cli.cfg = cfg
	}

	L.Push(pro)
	return 1
}
