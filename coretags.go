//go:build !(with_gvisor && with_quic && with_utls && with_clash_api)

package main

// Ядро sing-box встроено в программу, и без этих тегов в нём не будет TUN, Hysteria2, uTLS и API статистики.
// Собирать и тестировать так (теги — в файле CORE_TAGS):
//
//	go build -tags "$(cat CORE_TAGS)" ...
//	go test  -tags "$(cat CORE_TAGS)" ./...
const _ = нужны_теги_ядра_см_CORE_TAGS
