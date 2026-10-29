package main

import (
	"errors"
	"strings"
)

// Генератор QR-кодов без внешних библиотек: режим «байты», коррекция ошибок L, версии 1–20 (до 858 байт).

type qrBlocks struct {
	data   int // всего кодовых слов данных
	ec     int // слов коррекции на блок
	short  int // блоков с данными (data/blocks)
	nShort int // сколько коротких блоков
	nLong  int // сколько длинных (на слово длиннее)
}

// version -> блоки для уровня L
var qrL = [21]qrBlocks{
	{}, {19, 7, 19, 1, 0}, {34, 10, 34, 1, 0}, {55, 15, 55, 1, 0}, {80, 20, 80, 1, 0}, {108, 26, 108, 1, 0},
	{136, 18, 68, 2, 0}, {156, 20, 78, 2, 0}, {194, 24, 97, 2, 0}, {232, 30, 116, 2, 0}, {274, 18, 68, 2, 2},
	{324, 20, 81, 4, 0}, {370, 24, 92, 2, 2}, {428, 26, 107, 4, 0}, {461, 30, 115, 3, 1}, {523, 22, 87, 5, 1},
	{589, 24, 98, 5, 1}, {647, 28, 107, 1, 5}, {721, 30, 120, 5, 1}, {795, 28, 113, 3, 4}, {861, 28, 107, 3, 5},
}

var gfExp [512]byte
var gfLog [256]int

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = i
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[gfLog[a]+gfLog[b]]
}

func rsGenerator(deg int) []byte {
	g := []byte{1}
	for i := 0; i < deg; i++ {
		next := make([]byte, len(g)+1)
		for j, c := range g {
			next[j] ^= c
			next[j+1] ^= gfMul(c, gfExp[i])
		}
		g = next
	}
	return g // g[0] — старший коэффициент (1)
}

func rsRemainder(data []byte, deg int) []byte {
	g := rsGenerator(deg)
	rem := make([]byte, deg)
	for _, b := range data {
		f := b ^ rem[0]
		copy(rem, rem[1:])
		rem[deg-1] = 0
		if f != 0 {
			for i := 0; i < deg; i++ {
				rem[i] ^= gfMul(g[i+1], f)
			}
		}
	}
	return rem
}

func qrCapacity(ver int) int {
	bits := 8 * qrL[ver].data
	cc := 8
	if ver >= 10 {
		cc = 16
	}
	return (bits - 4 - cc) / 8
}

type bitBuf struct{ bits []bool }

func (b *bitBuf) add(v uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		b.bits = append(b.bits, v>>uint(i)&1 == 1)
	}
}

func qrCodewords(text []byte, ver int) []byte {
	var bb bitBuf
	bb.add(4, 4)
	if ver >= 10 {
		bb.add(uint32(len(text)), 16)
	} else {
		bb.add(uint32(len(text)), 8)
	}
	for _, c := range text {
		bb.add(uint32(c), 8)
	}
	capBits := 8 * qrL[ver].data
	term := capBits - len(bb.bits)
	if term > 4 {
		term = 4
	}
	bb.add(0, term)
	for len(bb.bits)%8 != 0 {
		bb.bits = append(bb.bits, false)
	}
	data := make([]byte, 0, qrL[ver].data)
	for i := 0; i < len(bb.bits); i += 8 {
		var v byte
		for j := 0; j < 8; j++ {
			v <<= 1
			if bb.bits[i+j] {
				v |= 1
			}
		}
		data = append(data, v)
	}
	for pad := byte(0xEC); len(data) < qrL[ver].data; pad ^= 0xEC ^ 0x11 {
		data = append(data, pad)
	}
	// блоки и коррекция
	info := qrL[ver]
	var blocks, ecs [][]byte
	pos := 0
	for i := 0; i < info.nShort+info.nLong; i++ {
		n := info.short
		if i >= info.nShort {
			n++
		}
		blk := data[pos : pos+n]
		pos += n
		blocks = append(blocks, blk)
		ecs = append(ecs, rsRemainder(blk, info.ec))
	}
	var out []byte
	maxLen := info.short + 1
	for i := 0; i < maxLen; i++ {
		for _, b := range blocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := 0; i < info.ec; i++ {
		for _, e := range ecs {
			out = append(out, e[i])
		}
	}
	return out
}

type qrMatrix struct {
	size int
	mod  [][]bool
	fn   [][]bool
}

func newQRMatrix(size int) *qrMatrix {
	m := &qrMatrix{size: size, mod: make([][]bool, size), fn: make([][]bool, size)}
	for i := range m.mod {
		m.mod[i] = make([]bool, size)
		m.fn[i] = make([]bool, size)
	}
	return m
}

func (m *qrMatrix) set(x, y int, v bool) {
	if x >= 0 && y >= 0 && x < m.size && y < m.size {
		m.mod[y][x], m.fn[y][x] = v, true
	}
}

func bitAt(v uint32, i int) bool { return v>>uint(i)&1 == 1 }

func (m *qrMatrix) finder(cx, cy int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			d := max(qrAbs(dx), qrAbs(dy))
			m.set(cx+dx, cy+dy, d != 2 && d != 4)
		}
	}
}

func (m *qrMatrix) alignment(cx, cy int) {
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			m.set(cx+dx, cy+dy, max(qrAbs(dx), qrAbs(dy)) != 1)
		}
	}
}

func qrAbs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

func qrAlignPositions(ver int) []int {
	if ver == 1 {
		return nil
	}
	n := ver/7 + 2
	step := (ver*4 + n*2 + 1) / (n*2 - 2) * 2
	size := ver*4 + 17
	res := make([]int, n)
	res[0] = 6
	for i, pos := n-1, size-7; i >= 1; i, pos = i-1, pos-step {
		res[i] = pos
	}
	return res
}

func (m *qrMatrix) drawFunctions(ver int) {
	for i := 0; i < m.size; i++ {
		m.set(6, i, i%2 == 0)
		m.set(i, 6, i%2 == 0)
	}
	m.finder(3, 3)
	m.finder(m.size-4, 3)
	m.finder(3, m.size-4)
	pos := qrAlignPositions(ver)
	last := len(pos) - 1
	for i, a := range pos {
		for j, b := range pos {
			if (i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0) {
				continue
			}
			m.alignment(a, b)
		}
	}
	m.drawFormat(0) // резерв под формат
	if ver >= 7 {
		rem := uint32(ver)
		for i := 0; i < 12; i++ {
			rem = rem<<1 ^ (rem>>11)*0x1F25
		}
		bits := uint32(ver)<<12 | rem
		for i := 0; i < 18; i++ {
			a, b := m.size-11+i%3, i/3
			m.set(a, b, bitAt(bits, i))
			m.set(b, a, bitAt(bits, i))
		}
	}
}

func (m *qrMatrix) drawFormat(mask int) {
	data := uint32(1)<<3 | uint32(mask) // уровень L = 01
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	bits := (data<<10 | rem) ^ 0x5412
	for i := 0; i <= 5; i++ {
		m.set(8, i, bitAt(bits, i))
	}
	m.set(8, 7, bitAt(bits, 6))
	m.set(8, 8, bitAt(bits, 7))
	m.set(7, 8, bitAt(bits, 8))
	for i := 9; i < 15; i++ {
		m.set(14-i, 8, bitAt(bits, i))
	}
	for i := 0; i < 8; i++ {
		m.set(m.size-1-i, 8, bitAt(bits, i))
	}
	for i := 8; i < 15; i++ {
		m.set(8, m.size-15+i, bitAt(bits, i))
	}
	m.set(8, m.size-8, true)
}

func (m *qrMatrix) placeData(cw []byte) {
	i := 0
	for right := m.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < m.size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				upward := (right+1)&2 == 0
				y := vert
				if upward {
					y = m.size - 1 - vert
				}
				if !m.fn[y][x] && i < len(cw)*8 {
					m.mod[y][x] = cw[i>>3]>>(7-uint(i&7))&1 == 1
					i++
				}
			}
		}
	}
}

func qrMaskBit(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	}
	return ((x+y)%2+x*y%3)%2 == 0
}

func (m *qrMatrix) applyMask(mask int) {
	for y := 0; y < m.size; y++ {
		for x := 0; x < m.size; x++ {
			if !m.fn[y][x] && qrMaskBit(mask, x, y) {
				m.mod[y][x] = !m.mod[y][x]
			}
		}
	}
}

func (m *qrMatrix) penalty() int {
	n, score := m.size, 0
	run := func(get func(i int) bool) {
		l := 1
		for i := 1; i < n; i++ {
			if get(i) == get(i-1) {
				l++
				continue
			}
			if l >= 5 {
				score += 3 + l - 5
			}
			l = 1
		}
		if l >= 5 {
			score += 3 + l - 5
		}
		// шаблон, похожий на искатель: 1011101 с четырьмя светлыми по одну сторону
		for i := 0; i+11 <= n; i++ {
			a, b := true, true
			p1 := []bool{true, false, true, true, true, false, true, false, false, false, false}
			p2 := []bool{false, false, false, false, true, false, true, true, true, false, true}
			for k := 0; k < 11; k++ {
				v := get(i + k)
				if v != p1[k] {
					a = false
				}
				if v != p2[k] {
					b = false
				}
			}
			if a {
				score += 40
			}
			if b {
				score += 40
			}
		}
	}
	for y := 0; y < n; y++ {
		y := y
		run(func(i int) bool { return m.mod[y][i] })
	}
	for x := 0; x < n; x++ {
		x := x
		run(func(i int) bool { return m.mod[i][x] })
	}
	dark := 0
	for y := 0; y < n-1; y++ {
		for x := 0; x < n-1; x++ {
			c := m.mod[y][x]
			if c == m.mod[y][x+1] && c == m.mod[y+1][x] && c == m.mod[y+1][x+1] {
				score += 3
			}
		}
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if m.mod[y][x] {
				dark++
			}
		}
	}
	total := n * n
	k := (qrAbs(dark*20-total*10)+total-1)/total - 1
	if k > 0 {
		score += k * 10
	}
	return score
}

// qrEncode returns the QR matrix (true = dark) for the text.
func qrEncode(text string) ([][]bool, error) {
	data := []byte(text)
	ver := 0
	for v := 1; v <= 20; v++ {
		if len(data) <= qrCapacity(v) {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, errors.New("текст слишком длинный для QR-кода")
	}
	cw := qrCodewords(data, ver)
	size := ver*4 + 17
	best, bestScore := (*qrMatrix)(nil), 1<<30
	for mask := 0; mask < 8; mask++ {
		m := newQRMatrix(size)
		m.drawFunctions(ver)
		m.placeData(cw)
		m.applyMask(mask)
		m.drawFormat(mask)
		if p := m.penalty(); p < bestScore {
			best, bestScore = m, p
		}
	}
	return best.mod, nil
}

// qrSVG draws the QR code as an SVG with a 4-module quiet zone.
func qrSVG(text string) (string, error) {
	mod, err := qrEncode(text)
	if err != nil {
		return "", err
	}
	n := len(mod)
	var sb strings.Builder
	sb.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 `)
	sb.WriteString(itoa(n + 8))
	sb.WriteString(" ")
	sb.WriteString(itoa(n + 8))
	sb.WriteString(`" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="`)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if mod[y][x] {
				sb.WriteString("M" + itoa(x+4) + " " + itoa(y+4) + "h1v1h-1z")
			}
		}
	}
	sb.WriteString(`"/></svg>`)
	return sb.String(), nil
}
