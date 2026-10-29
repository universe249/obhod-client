// Package winloader — заглушка: загрузка DLL из памяти не нужна, мы кладём WebView2Loader.dll на диск и грузим обычным способом.
package winloader

import "errors"

type Proc interface {
	Call(a ...uint64) (uint64, uint64, error)
}

type Module interface {
	Proc(name string) Proc
}

func LoadFromMemory(b []byte) (Module, error) {
	return nil, errors.New("загрузка из памяти не поддерживается")
}
