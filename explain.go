package main

import (
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
)

// Problem is a plain-language explanation of something found in the logs or the state.
type Problem struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Fix   string `json:"fix"`
	Count int    `json:"count"`
	Level string `json:"level"` // bad | warn
}

type pattern struct {
	id, title, fix, level string
	re                    *regexp.Regexp
}

var patterns = []pattern{
	{"port", "Порт уже занят другой программой",
		"Закрой вторую копию программы или другой VPN/прокси (v2rayN, Clash, Nekoray). Если не помогает — перезагрузи компьютер или отправь отчёт администратору в «Помощи».",
		"bad", regexp.MustCompile(`(?i)address already in use|only one usage of each socket|bind: |listen tcp .*: (bind|.*in use)`)},
	{"admin", "Не хватает прав администратора",
		"Закрой программу и запусти снова — когда Windows спросит разрешение, нажми «Да». Без этого туннель создать нельзя.",
		"bad", regexp.MustCompile(`(?i)access is denied|отказано в доступе|requires? administrator|operation requires elevation|privilege`)},
	{"tun", "Не создаётся виртуальный сетевой адаптер (TUN)",
		"Обычно мешает антивирус, брандмауэр или другой VPN с таким же адаптером (WARP, WireGuard). Выключи их на время проверки или добавь папку программы в исключения.",
		"bad", regexp.MustCompile(`(?i)(configure|create|open) tun|wintun|tun interface|start tun`)},
	{"unreach", "Сервер не отвечает",
		"Проверь на вкладке «Подключение» адрес и порт, что VPS включён и порт открыт в файрволе. Если интернет работает без туннеля — попробуй другой сервер из списка «Мои серверы».",
		"bad", regexp.MustCompile(`(?i)i/o timeout|connection refused|no route to host|network is unreachable|host is unreachable|подключение не установлено|попытка подключения была безуспешной`)},
	{"auth", "Сервер отклонил пароль или ключ",
		"Пароль, UUID или obfs-пароль не совпадают с настройками сервера. Импортируй ссылку заново из панели сервера.",
		"bad", regexp.MustCompile(`(?i)authentication failed|auth(entication)? error|invalid (user|uuid|password)|unauthorized|wrong password`)},
	{"cert", "Проблема с сертификатом сервера",
		"Проверь имя SNI на вкладке «Подключение». Если сертификат самоподписанный — включи «Не проверять сертификат». Ещё частая причина — неверные дата и время в Windows.",
		"bad", regexp.MustCompile(`(?i)x509|certificate|tls: (bad|handshake|failed)|unknown authority`)},
	{"reset", "Соединение рвётся на полпути",
		"Чаще всего провайдер обрывает соединения к серверу. Включи «Фрагментацию TLS» в Настройках или нажми «Подобрать способ» на вкладке «Подключение»; если не поможет — возьми сервер с другим протоколом из «Мои серверы» (Hysteria2 вместо VLESS или наоборот).",
		"warn", regexp.MustCompile(`(?i)connection reset|forcibly closed|wsarecv|broken pipe|unexpected eof|stream.*reset|принудительно разорвал`)},
	{"dns", "Не работает определение адресов (DNS)",
		"Проверь DNS на вкладке «Подключение» (раздел «Дополнительно»). Для обычного DNS подойдёт 77.88.8.8, для удалённого — 1.1.1.1. Антивирусы с «защитой DNS» тоже могут мешать.",
		"warn", regexp.MustCompile(`(?i)lookup .* (no such host|server misbehaving|timeout)|dns: .*(fail|timeout)|exchange failed`)},
	{"ruleset", "Не скачались списки сайтов",
		"Списки качаются через GitHub. Включи туннель и нажми «Обновить списки» на вкладке «Правила»; без них работают только свои домены и приложения.",
		"warn", regexp.MustCompile(`(?i)rule[-_ ]?set.*(fail|error|download|not found)|geosite.*(fail|error)|geoip.*(fail|error)`)},
	{"config", "Ошибка в настройках",
		"Программа не смогла собрать конфиг. Чаще всего помогает заново добавить ссылку на вкладке «Подключение». Если нет — отправь отчёт администратору в «Помощи».",
		"bad", regexp.MustCompile(`(?i)decode config|parse config|invalid config|unknown field|missing .* option|json: `)},
	{"xray", "Не запускается Xray (для xhttp-серверов)",
		"Скачай Xray в «Настройки → Обновления» и проверь, что порт 10808 свободен.",
		"bad", regexp.MustCompile(`(?i)xray.*(fail|error|exit|not found)|failed to start xray`)},
}

// explainText finds known problems in log text.
func explainText(text string) []Problem {
	var res []Problem
	lines := strings.Split(text, "\n")
	for _, p := range patterns {
		n := 0
		for _, l := range lines {
			u := strings.ToUpper(l)
			if !strings.Contains(u, "ERROR") && !strings.Contains(u, "WARN") && !strings.Contains(u, "FATAL") && !strings.Contains(u, "PANIC") && p.id != "port" && p.id != "admin" && p.id != "tun" {
				continue
			}
			if p.re.MatchString(l) {
				n++
			}
		}
		if n > 0 {
			res = append(res, Problem{ID: p.id, Title: p.title, Fix: p.fix, Count: n, Level: p.level})
		}
	}
	return res
}

// explainState adds problems visible from the state alone.
func (a *App) explainState() []Problem {
	st := a.settings()
	var res []Problem
	add := func(id, title, fix, lvl string) {
		res = append(res, Problem{ID: id, Title: title, Fix: fix, Count: 1, Level: lvl})
	}
	if !isAdmin() {
		add("admin", "Программа запущена без прав администратора", "Перезапусти её и разреши запуск в окне Windows.", "bad")
	}
	if st.Server.Host == "" {
		add("noserver", "Не задан сервер", "Открой «Подключение» и вставь ссылку на сервер или подписку (из бота или панели s-ui).", "bad")
	}
	if running, _, _, _, _ := a.core.Info(); !running && a.wanted() {
		add("stopped", "Туннель должен работать, но остановлен", "Нажми «Включить» и посмотри ошибку на главной.", "bad")
	}
	if v, ok := netHint.get(); ok {
		add("nethint", v.Title, v.Fix, "warn")
	}
	if h, _ := a.health.Get(); h == "bad" {
		fix := "Подожди минуту: программа сама попробует другой сервер или перезапустится. Если не проходит — проверь интернет без туннеля."
		if !st.Watchdog {
			fix = "Выключи и включи обход или выбери другой сервер. Чтобы программа делала это сама, включи «Следить за соединением» в Настройках."
		}
		add("health", "Связь с сервером сейчас пропала", fix, "bad")
	}
	return res
}

func (a *App) handleExplain(w http.ResponseWriter, r *http.Request) {
	var text string
	for _, f := range []string{"box.log", "core.out", "xray.log", "xray.out"} {
		text += "\n" + stripANSI(tailFile(filepath.Join(a.dataDir, f), 60000))
	}
	_, _, _, lastErr, _ := a.core.Info()
	if lastErr != "" {
		text += "\nERROR " + lastErr
	}
	probs := append(a.explainState(), explainText(text)...)
	if probs == nil {
		probs = []Problem{}
	}
	writeJSON(w, 200, map[string]any{"problems": probs})
}
