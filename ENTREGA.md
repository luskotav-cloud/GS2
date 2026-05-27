# 📦 Guia de Entrega — GS Coding for Security

Checklist e instruções para entregar o **OSINT Recon Agent** (entrega via **Teams**).

---

## ✅ Checklist da entrega

| # | Item exigido | Status |
|---|--------------|--------|
| 1 | Link do GitHub **ou** `.zip` do projeto | ✅ https://github.com/luskotav-cloud/GS2 |
| 2 | Todos os arquivos necessários para execução | ✅ no repositório |
| 3 | **Prints em funcionamento na sua máquina** | ⬜ você precisa tirar (passo a passo abaixo) |
| 4 | README com instruções **e prints** | ✅ instruções / ⬜ adicionar prints |

---

## 🎯 Pontuação coberta pelo projeto

**Base (8,0):**
- Agente criado com Agno ✅
- 7 tools funcionais reais ✅ (o mínimo pedido é 4)
- Integração agente ↔ tools ✅
- `.env` + `requirements.txt` + organização ✅
- Execução via CLI ✅
- Persistência (SQLite do Agno) ✅
- README com instruções ✅

**Extra (+2,0):**
- Containerização com Docker (`Dockerfile` + `docker-compose.yml`) ✅
- Interface web (Flask + Vue 3) ✅

---

## ▶️ Como rodar (para gerar os prints)

### Pré-requisito
Crie o `.env` a partir do exemplo e coloque sua chave Gemini:
```bash
copy .env.example .env        # Windows
# edite .env e preencha GEMINI_API_KEY=...   (chave gratuita em https://aistudio.google.com/apikey)
```

### 1. CLI
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```
Faça 2-3 perguntas, por exemplo:
- `faça whois de github.com`
- `enumere os subdominios de tesla.com`
- `analise o arquivo sample_suspeito.png`

### 2. Interface web
```bash
python server.py
```
Abra **http://localhost:5000**, envie uma mensagem e veja a resposta + o painel de tools.

### 3. Docker (extra)
```bash
docker compose up --build
```
Abra **http://localhost:5000**.

---

## 📸 Como tirar e anexar os prints

Tire screenshots (tecla **PrtSc** ou **Win+Shift+S**) de:

1. **CLI** — `python main.py` com uma pergunta respondida (mostrando uma tool sendo usada).
2. **Web** — navegador em `http://localhost:5000` com uma conversa e o painel de tools visível.
3. *(opcional)* **Docker** — terminal com `docker compose up` + navegador funcionando.

Salve os arquivos na pasta `prints/` do projeto, por exemplo:
```
prints/
├── cli.png
├── web.png
└── docker.png
```

Depois adicione ao final do `README.md` uma seção:
```markdown
## 📸 Prints de funcionamento

### CLI
![CLI](prints/cli.png)

### Interface Web
![Web](prints/web.png)

### Docker
![Docker](prints/docker.png)
```

Faça o commit dos prints:
```bash
git add prints README.md
git commit -m "docs: adiciona prints de funcionamento"
git push
```

---

## 📤 O que enviar no Teams

1. **Link do GitHub:** https://github.com/luskotav-cloud/GS2
2. **Prints** em funcionamento na sua máquina (os mesmos da pasta `prints/`).
3. (Opcional) Um `.zip` do projeto — gere com:
   ```bash
   git archive --format zip --output GS2.zip main
   ```

---

## ⚠️ Atenção

- **NÃO** suba o arquivo `.env` (ele contém a chave da API). Já está protegido pelo `.gitignore`.
- A chave Gemini usada durante o desenvolvimento deve ser **rotacionada** em https://aistudio.google.com/apikey se houver risco de exposição.
