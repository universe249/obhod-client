package main

// Service describes one group of sites/apps that can be routed through the proxy.
type Service struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Group   string   `json:"group"`
	Geosite []string `json:"geosite,omitempty"` // SagerNet/sing-geosite tags (without "geosite-")
	Domains []string `json:"domains,omitempty"` // extra domain suffixes
	CIDRs   []string `json:"cidrs,omitempty"`
	Apps    []string `json:"apps,omitempty"` // process names
	Default bool     `json:"default"`
}

var catalog = []Service{
	// Apex Legends: сама игра (матчи по UDP), вход и сервисы EA, античит. Программу EA app целиком не добавляем,
	// чтобы скачивание игры и обновлений (десятки ГБ) не шло через сервер и не съедало трафик.
	{ID: "apex", Name: "Apex Legends и EA", Group: "Игры", Default: true,
		Domains: []string{"ea.com", "origin.com", "respawn.com", "playapex.com", "easyanticheat.net", "easy.ac", "epicgames.dev"},
		Apps:    []string{"r5apex.exe", "r5apex_dx12.exe", "EasyAntiCheat.exe", "EasyAntiCheat_EOS.exe"}},
	{ID: "youtube", Name: "YouTube", Group: "Видео и музыка", Default: true,
		Geosite: []string{"youtube"},
		Domains: []string{"youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com"}},
	{ID: "discord", Name: "Discord", Group: "Общение", Default: true,
		// вложения Discord загружаются напрямую в облако Google — без этого адреса в браузерном Discord картинки не отправлялись
		Domains: []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discord-attachments-uploads-prd.storage.googleapis.com"},
		Apps:    []string{"Discord.exe", "Update.exe"}},
	{ID: "telegram", Name: "Telegram", Group: "Общение", Default: true,
		Geosite: []string{"telegram"},
		CIDRs: []string{"149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22",
			"91.108.16.0/22", "91.108.56.0/22", "95.161.64.0/20", "185.76.151.0/24"},
		Apps: []string{"Telegram.exe"}},
	{ID: "whatsapp", Name: "WhatsApp", Group: "Общение", Geosite: []string{"whatsapp"}},
	{ID: "signal", Name: "Signal", Group: "Общение", Geosite: []string{"signal"}},
	{ID: "instagram", Name: "Instagram", Group: "Соцсети", Default: true,
		Geosite: []string{"instagram"}, Domains: []string{"instagram.com", "cdninstagram.com"}},
	{ID: "facebook", Name: "Facebook / Meta", Group: "Соцсети", Default: true,
		Geosite: []string{"facebook", "meta"}, Domains: []string{"facebook.com", "fbcdn.net"}},
	{ID: "twitter", Name: "Twitter / X", Group: "Соцсети", Default: true,
		Geosite: []string{"twitter"}, Domains: []string{"twitter.com", "x.com", "t.co", "twimg.com"}},
	{ID: "tiktok", Name: "TikTok", Group: "Соцсети", Default: true,
		Geosite: []string{"tiktok"},
		Domains: []string{"tiktok.com", "tiktokv.com", "tiktokv.us", "tiktokw.us", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com",
			"byteoversea.com", "ibytedtos.com", "ibyteimg.com", "byteimg.com", "bytedance.com", "bytefcdn-oversea.com", "byted.org", "ttwstatic.com",
			"ttlivecdn.com", "musical.ly", "muscdn.com", "snssdk.com", "isnssdk.com", "pstatp.com"}},
	{ID: "linkedin", Name: "LinkedIn", Group: "Соцсети", Geosite: []string{"linkedin"}},
	{ID: "reddit", Name: "Reddit", Group: "Соцсети", Geosite: []string{"reddit"}},
	{ID: "twitch", Name: "Twitch", Group: "Видео и музыка", Geosite: []string{"twitch"}},
	{ID: "spotify", Name: "Spotify", Group: "Видео и музыка", Geosite: []string{"spotify"}},
	{ID: "netflix", Name: "Netflix", Group: "Видео и музыка", Geosite: []string{"netflix"}},
	{ID: "soundcloud", Name: "SoundCloud", Group: "Видео и музыка", Geosite: []string{"soundcloud"}},
	{ID: "openai", Name: "ChatGPT / OpenAI", Group: "ИИ и нейросети", Geosite: []string{"openai"}},
	{ID: "gemini", Name: "Google Gemini / AI Studio (весь Google через сервер)", Group: "ИИ и нейросети", Domains: []string{"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gvt1.com", "google.ru", "gemini.google.com", "bard.google.com", "aistudio.google.com", "makersuite.google.com", "ai.google.dev", "generativelanguage.googleapis.com", "notebooklm.google.com", "labs.google", "deepmind.google", "alkalimakersuite-pa.clients6.google.com", "robinfrontend-pa.googleapis.com"}},
	{ID: "claude", Name: "Claude / Anthropic", Group: "ИИ и нейросети", Domains: []string{"claude.ai", "anthropic.com", "claude.com", "claudeusercontent.com"}},
	{ID: "grok", Name: "Grok / xAI", Group: "ИИ и нейросети", Domains: []string{"grok.com", "x.ai"}},
	{ID: "copilot", Name: "Microsoft Copilot", Group: "ИИ и нейросети", Domains: []string{"copilot.microsoft.com", "copilot.cloud.microsoft", "bing.com", "sydney.bing.com"}},
	{ID: "perplexity", Name: "Perplexity", Group: "ИИ и нейросети", Domains: []string{"perplexity.ai", "pplx.ai"}},
	{ID: "mistral", Name: "Mistral / Le Chat", Group: "ИИ и нейросети", Domains: []string{"mistral.ai", "chat.mistral.ai"}},
	{ID: "metaai", Name: "Meta AI", Group: "ИИ и нейросети", Domains: []string{"meta.ai", "llama.com"}},
	{ID: "hf", Name: "Hugging Face", Group: "ИИ и нейросети", Domains: []string{"huggingface.co", "hf.co", "hf.space"}},
	{ID: "openrouter", Name: "OpenRouter", Group: "ИИ и нейросети", Domains: []string{"openrouter.ai"}},
	{ID: "poe", Name: "Poe", Group: "ИИ и нейросети", Domains: []string{"poe.com"}},
	{ID: "midjourney", Name: "Midjourney", Group: "ИИ и нейросети", Domains: []string{"midjourney.com"}},
	{ID: "characterai", Name: "Character.AI", Group: "ИИ и нейросети", Domains: []string{"character.ai", "beta.character.ai"}},
	{ID: "cursor", Name: "Cursor", Group: "ИИ и нейросети", Domains: []string{"cursor.com", "cursor.sh", "cursorapi.com"}},
	{ID: "githubcopilot", Name: "GitHub Copilot", Group: "ИИ и нейросети", Domains: []string{"githubcopilot.com", "copilot-proxy.githubusercontent.com"}},
	{ID: "cohere", Name: "Cohere", Group: "ИИ и нейросети", Domains: []string{"cohere.com", "cohere.ai"}},
	{ID: "elevenlabs", Name: "ElevenLabs", Group: "ИИ и нейросети", Domains: []string{"elevenlabs.io"}},
	{ID: "suno", Name: "Suno", Group: "ИИ и нейросети", Domains: []string{"suno.com", "suno.ai"}},
	{ID: "runway", Name: "Runway / Pika / Luma", Group: "ИИ и нейросети", Domains: []string{"runwayml.com", "pika.art", "lumalabs.ai"}},
	{ID: "notion", Name: "Notion", Group: "Прочее", Geosite: []string{"notion"}},
	{ID: "medium", Name: "Medium", Group: "Прочее", Geosite: []string{"medium"}},
	{ID: "patreon", Name: "Patreon", Group: "Прочее", Geosite: []string{"patreon"}},
	{ID: "bbc", Name: "BBC", Group: "Прочее", Geosite: []string{"bbc"}},
}
