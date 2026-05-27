# OSINT Recon Agent 🕵️

Agente de IA para **OSINT (Open Source Intelligence) e forense digital**, desenvolvido com o framework **[Agno](https://github.com/agno-agi/agno)**. Suporta dois providers de modelo (escolha via `.env`): **Gemini API** (`gemini-flash-latest`, padrão — cloud e rápido) ou **Ollama local** (`qwen2.5:3b` — fallback offline).

Projeto da **GS — Coding for Security (2º Semestre)**.

O agente recebe comandos em linguagem natural, decide qual ferramenta usar, executa ações **reais** (requisições HTTP, consultas WHOIS, análise binária de arquivos) e mantém o **contexto da conversa** entre as perguntas.

---

## 🧰 Tools implementadas (14)

| Tool | O que faz |
|------|-----------|
| `search_subdomains_crt` | Enumera subdomínios **passivamente** via Certificate Transparency (API pública do **crt.sh**), com retry e match exato de sufixo. |
| `verify_username_presence` | Verifica em quais plataformas (GitHub, GitLab, Reddit, Hacker News, Keybase) um **username** existe, por **conteúdo/JSON** das APIs (sem falsos 200 de login walls). |
| `get_whois_info` | Consulta dados de registro **WHOIS** (criação, expiração, registrar, org, país, emails, name servers) via `python-whois`. |
| `check_wayback_machine` | Verifica snapshots arquivados de um site no **Internet Archive (Wayback Machine)**. |
| `analyze_file_steganography` | Mini-**Binwalk** em Python puro: detecta **dados anexados após o EOF** (IEND/FFD9) e varre **Magic Bytes confiáveis** de containers embutidos (ZIP, RAR, 7z, PDF, GZIP, ELF, PNG). |
| `analyze_http_security_headers` *(extra)* | Analisa cabeçalhos de segurança HTTP (HSTS, CSP, X-Frame-Options…), aponta os ausentes e dá uma nota (A–D). |
| `resolve_dns` *(extra)* | Resolve um domínio para IPs **IPv4 (A) e IPv6 (AAAA)** e faz **DNS reverso (PTR)**. |
| `fuzz_web_paths` *(fuzzing)* | **Content discovery** estilo **ffuf/gobuster**: usa a wordlist real `common.txt` do **SecLists** (~4700 paths, baixada e cacheada automaticamente), 60 threads, e lista em tabela todo caminho ≠ 404 (status + tamanho), filtrando soft-404. |
| `fuzz_subdomains_dns` *(fuzzing)* | Brute-force **ativo** de subdomínios via DNS (wordlist embutida), complementando o crt.sh passivo. Reporta os que resolvem e seus IPs. |
| `query_dns_records` *(extra)* | Consulta registros DNS **A, AAAA, MX, NS, TXT, CNAME, SOA** via `dnspython` (reconhecimento de infraestrutura). |
| `ip_geolocation` *(extra)* | Geolocaliza um IP/domínio via **ipinfo.io**: cidade, país, organização/ASN, coordenadas e fuso. |
| `github_user_info` *(extra)* | Coleta o perfil público do **GitHub** (nome, bio, empresa, local, repos, seguidores, data de criação) via API oficial. |
| `expand_short_url` *(extra)* | Expande URLs encurtadas (bit.ly, t.co…) revelando a **cadeia de redirects** e o destino final — útil contra phishing. |
| `reverse_ip_lookup` *(extra)* | **Reverse IP lookup** (HackerTarget): lista outros domínios hospedados no mesmo IP (infra compartilhada). |

> As tools executam ações reais — nenhuma resposta é simulada ou fixa.
> Algumas se inspiram em toolkits OSINT de referência (ex.: EagleOsint), mas
> foram reescritas com APIs confiáveis e tratamento de erros próprio.

---

## 📦 Estrutura do projeto

```
GS2/
├── main.py            # CLI interativa (estilo chat)
├── server.py          # Servidor Flask (API + interface web)
├── agent.py           # Fábrica do agente Agno (modelo, tools, persistência)
├── tools.py           # As 14 tools de OSINT/forense
├── templates/
│   └── index.html     # Front-end em Vue 3 (via CDN)
├── requirements.txt
├── .env.example
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## ✅ Pré-requisitos

1. **Python 3.10+**
2. **Um provider de modelo** (escolha um):
   - **Gemini API** (recomendado): chave gratuita em https://aistudio.google.com/apikey
   - **Ollama local** (fallback): [Ollama](https://ollama.com/) instalado + `ollama pull qwen2.5:3b`

---

## 🚀 Instalação

```bash
# 1. Criar e ativar o ambiente virtual
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# 2. Instalar dependências
pip install -r requirements.txt

# 3. Configurar variáveis de ambiente
copy .env.example .env      # Windows
# cp .env.example .env      # Linux/Mac
```

Edite o `.env` se necessário (modelo, host do Ollama, porta do Flask).

---

## 💻 Uso — CLI (obrigatório)

```bash
python main.py
```

Exemplos de comandos:
- `enumere os subdominios de tesla.com`
- `o usuario torvalds existe em quais plataformas?`
- `faça whois de google.com`
- `o site exemplo.com tem snapshot no wayback?`
- `analise o arquivo sample_suspeito.png`
- `faça fuzzing de diretorios em exemplo.com`
- `brute force de subdominios de tesla.com`
- `mostre os registros DNS (MX, NS, TXT) de github.com`
- `onde fica o IP 8.8.8.8?`
- `me mostre o perfil github do torvalds`
- `pra onde aponta esse link bit.ly/xxxx?`
- `quais dominios estao no mesmo IP de github.com?`

Comandos especiais: `/new` (nova sessão), `/help` (lista tools), `/sair`.

---

## 🌐 Uso — Interface Web (extra +1,0)

```bash
python server.py
```

Acesse **http://127.0.0.1:5000**. Interface em **Vue 3** com:
- formulário de chat para envio de mensagens;
- exibição das respostas do agente (com markdown);
- painel lateral com as tools disponíveis;
- **botão de anexo (📎)** para enviar um arquivo e rodar a análise forense de esteganografia;
- botão de nova sessão.

---

## 🐳 Docker (extra +1,0)

> A chave da API **não** é embutida na imagem — é passada em tempo de execução
> via `--env-file .env` (o `.env` fica fora do build context). Com Gemini, o
> container não precisa de GPU nem do Ollama.

**Opção A — docker compose (mais simples):**
```bash
docker compose up --build
# -> http://localhost:5000
```

**Opção B — docker build/run:**
```bash
# Build
docker build -t osint-agent .

# Interface web (Windows / Docker Desktop)
docker run --rm -p 5000:5000 --env-file .env osint-agent
# -> http://localhost:5000

# CLI interativa
docker run --rm -it --env-file .env osint-agent python main.py
```

**Fallback para Ollama local** (em vez de Gemini), apontando para o host Windows:
```bash
docker run --rm -p 5000:5000 -e MODEL_PROVIDER=ollama ^
  -e OLLAMA_HOST=http://host.docker.internal:11434 osint-agent
```

---

## ⚙️ Variáveis de ambiente (`.env`)

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `MODEL_PROVIDER` | Provider do modelo: `gemini` ou `ollama` | `gemini` (se houver `GEMINI_API_KEY`) |
| `GEMINI_API_KEY` | Chave da API Gemini ([AI Studio](https://aistudio.google.com/apikey)) | — |
| `GEMINI_MODEL` | Modelo Gemini | `gemini-flash-latest` |
| `OLLAMA_MODEL` | Modelo Ollama (fallback local) | `qwen2.5:3b` |
| `OLLAMA_HOST` | Endpoint do Ollama | `http://localhost:11434` |
| `AGENT_DB_FILE` | Arquivo SQLite de sessões | `agent_sessions.db` |
| `AGENT_NAME` | Nome do agente | `OSINT Recon Agent` |
| `NUM_HISTORY_RUNS` | Nº de turnos mantidos no contexto | `5` |
| `FLASK_HOST` / `FLASK_PORT` | Bind do servidor web | `127.0.0.1` / `5000` |

---

## 🗄️ Persistência

O histórico de cada sessão é gravado em **SQLite** (`agent_sessions.db`) pelo próprio Agno, permitindo que o agente lembre o contexto entre as perguntas.

---

## ⚠️ Aviso ético

Ferramentas de uso defensivo / investigação autorizada. Use apenas em alvos próprios ou com permissão explícita.

---

## 📸 Prints de execução

CLI enumerando subdomínios de `fiap.com.br` (modelo Gemini + framework Agno):

![CLI — agente recebendo o comando de enumeração de subdomínios](GS02%20Prints/Captura%20de%20tela%202026-05-27%20110550.png)

![CLI — agente acionando a tool search_subdomains_crt](GS02%20Prints/Captura%20de%20tela%202026-05-27%20110653.png)
