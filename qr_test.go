package main

import (
	"os"
	"strings"
	"testing"
)

func TestQRBasics(t *testing.T) {
	if _, err := qrEncode(strings.Repeat("a", 900)); err == nil {
		t.Fatal("ожидалась ошибка для длинного текста")
	}
	m, err := qrEncode("hello")
	if err != nil || len(m) != 21 {
		t.Fatalf("v1: %v %d", err, len(m))
	}
	for v := 1; v <= 20; v++ {
		if qrCapacity(v) <= 0 {
			t.Fatal(v)
		}
		i := qrL[v]
		if got := i.nShort*i.short + i.nLong*(i.short+1); got != i.data {
			t.Fatalf("v%d данные %d != %d", v, got, i.data)
		}
	}
}

// QR_DUMP=dir — выгрузить матрицы для проверки внешним декодером.
func TestQRDump(t *testing.T) {
	dir := os.Getenv("QR_DUMP")
	if dir == "" {
		t.Skip()
	}
	for i, n := range []int{858, 820, 100} {
		s := strings.Repeat("vless://x-Ж_", 100)[:0]
		for len(s) < n {
			s += "vless://abc-123?x=" + string(rune('a'+len(s)%26))
		}
		s = s[:n]
		m, err := qrEncode(s)
		if err != nil {
			t.Fatal(n, err)
		}
		var sb strings.Builder
		sb.WriteString(s + "\n")
		for _, r := range m {
			for _, c := range r {
				if c {
					sb.WriteByte('1')
				} else {
					sb.WriteByte('0')
				}
			}
			sb.WriteByte('\n')
		}
		os.WriteFile(dir+"/q"+itoa(i)+".txt", []byte(sb.String()), 0o644)
	}
}
