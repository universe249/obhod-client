//go:build !windows

package main

// hotkeyRegister: глобальные сочетания есть только в Windows; здесь всё «успешно», чтобы проект собирался и проверялся на Linux.
func hotkeyRegister(binds map[string][2]uint32, fire func(action string)) map[string]string {
	out := map[string]string{}
	for id := range binds {
		out[id] = ""
	}
	return out
}
