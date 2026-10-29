package main

// Встроенное ядро. sing-box собран прямо в программу как библиотека (github.com/sagernet/sing-box), отдельного
// sing-box.exe больше нет. Ядро работает во втором экземпляре этой же программы, запущенном с ключом -core:
// если в ядре случится паника, упадёт только этот процесс, а окно останется, увидит падение и перезапустит туннель.
//
//   <программа> -core run   -c config.json -D data
//   <программа> -core check -c config.json -D data
//   <программа> -core version

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

const coreFlag = "-core"

// embeddedCoreVersion — версия sing-box, вшитая в программу (из go.mod; в сборках без модулей — константа C.Version).
func embeddedCoreVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/sagernet/sing-box" {
				v := d.Version
				if d.Replace != nil && d.Replace.Version != "" {
					v = d.Replace.Version
				}
				return "sing-box " + strings.TrimPrefix(v, "v")
			}
		}
	}
	return "sing-box " + C.Version
}

// coreMain выполняет команду ядра и возвращает код выхода.
func coreMain(args []string, stdout, stderr io.Writer) int {
	C.Version = strings.TrimPrefix(embeddedCoreVersion(), "sing-box ") // иначе API ядра отвечает «unknown»
	if len(args) == 0 {
		fmt.Fprintln(stderr, "нужна команда: run, check или version")
		return 2
	}
	cmd, cfgPath, dir := args[0], "config.json", ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-c", "--config":
			if i+1 < len(args) {
				i++
				cfgPath = args[i]
			}
		case "-D", "--directory":
			if i+1 < len(args) {
				i++
				dir = args[i]
			}
		}
	}
	if cmd == "version" {
		fmt.Fprintln(stdout, embeddedCoreVersion())
		return 0
	}
	if dir != "" {
		_ = os.MkdirAll(dir, 0o755)
		if err := os.Chdir(dir); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	var err error
	switch cmd {
	case "check":
		err = coreCheck(cfgPath)
	case "run":
		err = coreRun(cfgPath)
	default:
		err = errors.New("неизвестная команда ядра: " + cmd)
	}
	if err != nil {
		fmt.Fprintln(stderr, "FATAL", err)
		return 1
	}
	return 0
}

func coreContext() context.Context {
	return include.Context(service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger())))
}

func coreOptions(ctx context.Context, path string) (option.Options, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return option.Options{}, fmt.Errorf("read config at %s: %w", path, err)
	}
	return parseCoreOptions(ctx, b)
}

func parseCoreOptions(ctx context.Context, b []byte) (option.Options, error) {
	o, err := json.UnmarshalExtendedContext[option.Options](ctx, b)
	if err != nil {
		return option.Options{}, fmt.Errorf("decode config: %w", err)
	}
	return o, nil
}

// checkCoreConfig проверяет конфиг так же, как «sing-box check»: разбирает и создаёт (не запуская) все службы.
func checkCoreConfig(b []byte) error {
	ctx := coreContext()
	o, err := parseCoreOptions(ctx, b)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithCancel(service.ExtendContext(ctx))
	defer cancel()
	inst, err := box.New(box.Options{Context: cctx, Options: o})
	if err != nil {
		return err
	}
	return inst.Close()
}

func coreCheck(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return checkCoreConfig(b)
}

func coreRun(path string) error {
	ctx := coreContext()
	o, err := coreOptions(ctx, path)
	if err != nil {
		return err
	}
	if o.Log == nil {
		o.Log = &option.LogOptions{}
	}
	o.Log.DisableColor = true
	rctx, cancel := context.WithCancel(service.ExtendContext(ctx))
	defer cancel()
	inst, err := box.New(box.Options{Context: rctx, Options: o})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return fmt.Errorf("start service: %w", err)
	}
	debug.FreeOSMemory()
	// Окно закрывает ядро через TerminateProcess; на Linux (тесты) — сигналом. Ещё ядро завершается, если окно
	// закрыло наш stdin (его держит только окно) — так ядро не останется висеть без хозяина.
	stdinGone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(stdinGone)
	}()
	select {
	case <-sig:
	case <-stdinGone:
	}
	cancel()
	done := make(chan struct{})
	go func() {
		_ = inst.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(C.FatalStopTimeout):
	}
	return nil
}

// runCoreInProcess запускает ядро прямо в этом процессе (для тестов и проверок). Close останавливает его.
func runCoreInProcess(b []byte) (io.Closer, error) {
	ctx := coreContext()
	o, err := parseCoreOptions(ctx, b)
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithCancel(service.ExtendContext(ctx))
	inst, err := box.New(box.Options{Context: rctx, Options: o})
	if err != nil {
		cancel()
		return nil, err
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		cancel()
		return nil, err
	}
	return closerFunc(func() error { defer cancel(); return inst.Close() }), nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
