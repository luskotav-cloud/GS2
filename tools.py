"""
tools.py — Ferramentas (tools) de OSINT e Forense para o agente de IA.

Cada função abaixo é uma tool real, registrada no agente Agno.
Todas executam ações reais (requisições HTTP, leitura binária de arquivos,
consultas WHOIS e DNS), nunca retornam respostas fixas/simuladas.

Tema do agente: Reconhecimento e Forense Digital (OSINT Security Agent).
"""

import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# User-Agent comum para evitar bloqueios triviais de algumas plataformas.
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}
TIMEOUT = 20


def _session(retries: int = 2, backoff: float = 0.6) -> requests.Session:
    """Cria uma Session HTTP com retry automático em falhas de rede/5xx.

    Evita que APIs lentas ou instáveis (ex.: crt.sh) derrubem a tool numa
    única tentativa. Reaplica a requisição com backoff exponencial.
    """
    s = requests.Session()
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update(HEADERS)
    return s


def _clean_domain(domain: str) -> str:
    """Normaliza um domínio: remove esquema, www, barras e espaços."""
    domain = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].strip("/")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


# ---------------------------------------------------------------------------
# Tool 1 — Enumeração de subdomínios via Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------
def search_subdomains_crt(domain: str) -> str:
    """Enumera subdomínios de um domínio consultando logs de Certificate
    Transparency através da API pública do crt.sh.

    Faz uma requisição HTTP para https://crt.sh/?q=%25.<dominio>&output=json,
    extrai todos os 'name_value' dos certificados emitidos e retorna a lista
    de subdomínios ÚNICOS realmente pertencentes ao domínio alvo.

    Args:
        domain: Domínio alvo, ex: "tesla.com" (sem http:// e sem www).

    Returns:
        Texto com a contagem e a lista de subdomínios únicos descobertos.
    """
    domain = _clean_domain(domain)
    if not domain or "." not in domain:
        return f"[crt.sh] Domínio inválido: '{domain}'."

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    # crt.sh é lento; damos mais tempo e contamos com o retry da Session.
    try:
        resp = _session().get(url, timeout=40)
    except requests.RequestException as e:
        return f"[crt.sh] Erro de rede (crt.sh costuma ser lento): {e}"

    if resp.status_code != 200:
        return f"[crt.sh] Falha na consulta. Status code: {resp.status_code}"

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        return "[crt.sh] Resposta vazia ou inválida (nenhum certificado encontrado)."

    subdomains = set()
    for entry in data:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            # Match exato: o nome deve SER o domínio ou um subdomínio dele.
            # Evita capturar "eviltesla.com" ao buscar por "tesla.com".
            if name == domain or name.endswith("." + domain):
                subdomains.add(name)

    if not subdomains:
        return f"[crt.sh] Nenhum subdomínio encontrado para {domain}."

    ordered = sorted(subdomains)
    listing = "\n".join(f"  - {s}" for s in ordered)
    return f"[crt.sh] {len(ordered)} subdomínios únicos encontrados para {domain}:\n{listing}"


# ---------------------------------------------------------------------------
# Tool 2 — Verificação de presença de username em plataformas
# ---------------------------------------------------------------------------
def verify_username_presence(username: str) -> str:
    """Verifica em quais plataformas um determinado username existe.

    Faz requisições HTTP reais e usa verificação por CONTEÚDO/JSON (não apenas
    status code) para evitar falsos positivos de plataformas que respondem 200
    mesmo para perfis inexistentes. Cobre GitHub, GitLab, Reddit e Hacker News
    — todas com checagem de existência confiável.

    Args:
        username: Nome de usuário a investigar, ex: "torvalds".

    Returns:
        Texto indicando em quais plataformas o username foi encontrado.
    """
    username = username.strip().lstrip("@")
    if not username:
        return "[username] Informe um nome de usuário."

    sess = _session()
    results = []

    def check(name: str, exists: bool | None, url: str):
        if exists is True:
            results.append(f"  [+] ENCONTRADO  {name:<10} -> {url}")
        elif exists is False:
            results.append(f"  [-] livre       {name:<10} (não existe)")
        else:
            results.append(f"  [?] incerto     {name:<10} (falha ao verificar)")

    # GitHub — API oficial: 200 = existe, 404 = não existe (confiável).
    try:
        r = sess.get(f"https://api.github.com/users/{username}", timeout=TIMEOUT)
        check("GitHub", r.status_code == 200 if r.status_code in (200, 404) else None,
              f"https://github.com/{username}")
    except requests.RequestException:
        check("GitHub", None, "")

    # GitLab — API oficial: lista de usuários por username exato.
    try:
        r = sess.get(f"https://gitlab.com/api/v4/users?username={username}", timeout=TIMEOUT)
        found = r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) > 0
        check("GitLab", found if r.status_code == 200 else None,
              f"https://gitlab.com/{username}")
    except (requests.RequestException, ValueError):
        check("GitLab", None, "")

    # Reddit — endpoint about.json: existe se houver 'data' com 'name'.
    try:
        r = sess.get(f"https://www.reddit.com/user/{username}/about.json", timeout=TIMEOUT)
        if r.status_code == 200:
            payload = r.json().get("data", {})
            found = bool(payload.get("name")) and not payload.get("is_suspended", False)
            check("Reddit", found, f"https://www.reddit.com/user/{username}")
        elif r.status_code == 404:
            check("Reddit", False, "")
        else:
            check("Reddit", None, "")
    except (requests.RequestException, ValueError):
        check("Reddit", None, "")

    # Hacker News — Firebase API: retorna null (None) se não existe.
    try:
        r = sess.get(f"https://hacker-news.firebaseio.com/v0/user/{username}.json",
                     timeout=TIMEOUT)
        if r.status_code == 200:
            check("HackerNews", r.json() is not None,
                  f"https://news.ycombinator.com/user?id={username}")
        else:
            check("HackerNews", None, "")
    except (requests.RequestException, ValueError):
        check("HackerNews", None, "")

    return f"Verificação do username '{username}':\n" + "\n".join(results)


# ---------------------------------------------------------------------------
# Tool 3 — Consulta WHOIS de domínio
# ---------------------------------------------------------------------------
def get_whois_info(domain: str) -> str:
    """Consulta os dados de registro WHOIS de um domínio.

    Usa a biblioteca python-whois para obter data de criação, expiração,
    registrar, e-mails de contato e name servers do domínio informado.

    Args:
        domain: Domínio alvo, ex: "google.com".

    Returns:
        Texto com Creation Date, Expiration, Registrar, Emails e Name Servers.
    """
    import whois  # python-whois

    domain = _clean_domain(domain)
    if not domain or "." not in domain:
        return f"[WHOIS] Domínio inválido: '{domain}'."

    try:
        w = whois.whois(domain)
    except Exception as e:
        return f"[WHOIS] Erro ao consultar {domain}: {e}"

    # Se o registro não tem dados básicos, o domínio provavelmente não existe.
    if not w or not w.get("domain_name"):
        return f"[WHOIS] Nenhum registro WHOIS encontrado para '{domain}' (domínio pode não existir)."

    def fmt(value):
        if isinstance(value, (list, tuple, set)):
            seen = []
            for v in value:
                s = str(v)
                if s not in seen:
                    seen.append(s)
            return ", ".join(seen) if seen else "N/A"
        return str(value) if value else "N/A"

    return (
        f"[WHOIS] Registro de {domain}:\n"
        f"  Creation Date : {fmt(w.creation_date)}\n"
        f"  Expiration    : {fmt(w.expiration_date)}\n"
        f"  Registrar     : {fmt(w.registrar)}\n"
        f"  Org           : {fmt(w.get('org'))}\n"
        f"  Country       : {fmt(w.get('country'))}\n"
        f"  Emails        : {fmt(w.emails)}\n"
        f"  Name Servers  : {fmt(w.name_servers)}"
    )


# ---------------------------------------------------------------------------
# Tool 4 — Verificação de snapshots no Wayback Machine
# ---------------------------------------------------------------------------
def check_wayback_machine(url: str) -> str:
    """Verifica se um site possui snapshots arquivados no Internet Archive.

    Consulta a API pública https://archive.org/wayback/available?url=<url>
    para descobrir se o site suspeito foi arquivado e retorna a URL do
    snapshot disponível mais próximo.

    Args:
        url: Site/URL a verificar, ex: "exemplo-suspeito.com".

    Returns:
        Texto com o snapshot encontrado (URL e timestamp) ou aviso de ausência.
    """
    target = url.strip()
    if not target:
        return "[Wayback] Informe uma URL."

    api = "https://archive.org/wayback/available"
    try:
        resp = _session().get(api, params={"url": target}, timeout=TIMEOUT)
        data = resp.json()
    except requests.RequestException as e:
        return f"[Wayback] Erro de rede: {e}"
    except (json.JSONDecodeError, ValueError):
        return "[Wayback] Resposta inválida do Internet Archive."

    snapshot = data.get("archived_snapshots", {}).get("closest")
    if not snapshot or not snapshot.get("available"):
        return f"[Wayback] Nenhum snapshot arquivado encontrado para '{target}'."

    ts = snapshot.get("timestamp", "")
    try:
        readable = datetime.strptime(ts, "%Y%m%d%H%M%S").strftime("%d/%m/%Y %H:%M:%S")
    except ValueError:
        readable = ts

    return (
        f"[Wayback] Snapshot encontrado para '{target}':\n"
        f"  Data    : {readable}\n"
        f"  Status  : {snapshot.get('status')}\n"
        f"  URL     : {snapshot.get('url')}"
    )


# ---------------------------------------------------------------------------
# Tool 5 — Análise forense de arquivos embutidos (mini-Binwalk em Python puro)
# ---------------------------------------------------------------------------
# Assinaturas (Magic Bytes) CONFIÁVEIS de containers/arquivos que são
# carregadores típicos de esteganografia. Só usamos magics longos e
# distintivos (>=4 bytes) para NÃO gerar falsos positivos com bytes aleatórios
# (o motivo de "MZ"/"ID3" gerarem ruído em qualquer arquivo grande).
EMBEDDED_SIGNATURES = {
    b"\x50\x4b\x03\x04": "Arquivo ZIP/Office/APK (PK\\x03\\x04)",
    b"\x50\x4b\x05\x06": "Arquivo ZIP vazio (End Of Central Dir)",
    b"\x52\x61\x72\x21\x1a\x07\x00": "Arquivo RAR v4",
    b"\x52\x61\x72\x21\x1a\x07\x01\x00": "Arquivo RAR v5",
    b"\x37\x7a\xbc\xaf\x27\x1c": "Arquivo 7-Zip",
    b"\x25\x50\x44\x46\x2d": "Documento PDF (%PDF-)",
    b"\x7f\x45\x4c\x46": "Executável Linux (ELF)",
    b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a": "Imagem PNG embutida",
    b"\x1f\x8b\x08\x00": "Arquivo GZIP",
}

# Assinaturas só para IDENTIFICAR o tipo do header (não para varredura).
HEADER_SIGNATURES = {
    b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a": "Imagem PNG",
    b"\xff\xd8\xff": "Imagem JPEG",
    b"\x47\x49\x46\x38": "Imagem GIF",
    b"\x50\x4b\x03\x04": "Arquivo ZIP/Office",
    b"\x25\x50\x44\x46\x2d": "Documento PDF",
    b"\x4d\x5a": "Executável Windows (MZ/PE)",
    b"\x7f\x45\x4c\x46": "Executável Linux (ELF)",
}

# Marcador de fim-de-arquivo por tipo. Bytes APÓS o marcador = dados anexados
# (forte indício de esteganografia / arquivo escondido por concatenação).
EOF_MARKERS = {
    "Imagem PNG": b"\x49\x45\x4e\x44\xae\x42\x60\x82",  # chunk IEND completo
    "Imagem JPEG": b"\xff\xd9",                          # marcador EOI
}


def analyze_file_steganography(filepath: str) -> str:
    """Analisa um arquivo em busca de outros arquivos ocultos/embutidos (esteganografia).

    Funciona como um mini-Binwalk em Python puro. Faz DUAS análises reais:

    1. Dados anexados: detecta bytes existentes APÓS o marcador legítimo de
       fim-de-arquivo (IEND em PNG, EOI/FFD9 em JPEG). É a técnica de stego mais
       comum (concatenar um .zip no fim de uma imagem).
    2. Containers embutidos: varre todo o binário por assinaturas confiáveis
       de ZIP, RAR, 7z, PDF, GZIP, ELF e PNG em offsets posteriores ao início.

    Usa apenas magic bytes longos e distintivos para evitar falsos positivos
    (assinaturas curtas como "MZ" casam com bytes aleatórios em qualquer arquivo).

    Args:
        filepath: Caminho do arquivo a analisar, ex: "imagem.png".

    Returns:
        Texto indicando se o arquivo está limpo ou os arquivos ocultos achados.
    """
    filepath = filepath.strip().strip('"').strip("'")
    try:
        with open(filepath, "rb") as f:
            content = f.read()
    except FileNotFoundError:
        return f"[Forense] Arquivo não encontrado: {filepath}"
    except OSError as e:
        return f"[Forense] Erro ao abrir o arquivo: {e}"

    if not content:
        return f"[Forense] Arquivo vazio: {filepath}"

    # Tipo pelo header.
    header_type = "desconhecido"
    for sig, desc in HEADER_SIGNATURES.items():
        if content.startswith(sig):
            header_type = desc
            break

    findings = []

    # --- Análise 1: dados anexados após o fim-de-arquivo legítimo -----------
    appended = None
    marker = EOF_MARKERS.get(header_type)
    if marker:
        last = content.rfind(marker)
        if last != -1:
            eof = last + len(marker)
            trailing = len(content) - eof
            if trailing > 0:
                appended = (eof, trailing)

    # --- Análise 2: containers embutidos em offsets posteriores -------------
    for sig, desc in EMBEDDED_SIGNATURES.items():
        start = 1  # offset 0 = assinatura legítima do próprio arquivo
        while True:
            idx = content.find(sig, start)
            if idx == -1:
                break
            findings.append((idx, desc, sig.hex()))
            start = idx + 1

    summary = (
        f"[Forense] Análise de '{filepath}'\n"
        f"  Tamanho      : {len(content)} bytes\n"
        f"  Tipo (header): {header_type}\n"
    )

    if not appended and not findings:
        return summary + "  Resultado    : LIMPO — nenhum dado anexado ou arquivo embutido detectado."

    lines = []
    if appended:
        eof, trailing = appended
        lines.append(
            f"    [ANEXADO] {trailing} byte(s) após o fim do arquivo "
            f"(offset {eof} / 0x{eof:X}) — possível payload concatenado."
        )
    if findings:
        findings.sort(key=lambda x: x[0])
        for off, desc, hx in findings:
            lines.append(f"    [EMBUTIDO] offset {off} (0x{off:X}): {desc} [magic {hx}]")

    n = len(lines)
    return (
        summary
        + f"  Resultado    : SUSPEITO — {n} indício(s) de conteúdo oculto:\n"
        + "\n".join(lines)
    )


# ---------------------------------------------------------------------------
# Tool extra 6 — Análise de cabeçalhos de segurança HTTP
# ---------------------------------------------------------------------------
def analyze_http_security_headers(url: str) -> str:
    """Analisa os cabeçalhos de segurança HTTP de um site.

    Faz uma requisição real e verifica a presença de cabeçalhos de segurança
    importantes (HSTS, CSP, X-Frame-Options, etc.), apontando os que faltam
    e atribuindo uma nota (score).

    Args:
        url: Site a analisar, ex: "github.com" ou "https://github.com".

    Returns:
        Texto com os cabeçalhos de segurança presentes e ausentes.
    """
    url = url.strip()
    if not url:
        return "[Headers] Informe uma URL."
    if not url.startswith("http"):
        url = "https://" + url

    try:
        resp = _session().get(url, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        return f"[Headers] Erro de rede: {e}"

    wanted = {
        "Strict-Transport-Security": "HSTS (força HTTPS)",
        "Content-Security-Policy": "CSP (mitiga XSS)",
        "X-Frame-Options": "Anti-clickjacking",
        "X-Content-Type-Options": "Anti MIME-sniffing",
        "Referrer-Policy": "Controle de Referer",
        "Permissions-Policy": "Controle de APIs do navegador",
    }
    present, missing = [], []
    for h, desc in wanted.items():
        if h in resp.headers:
            present.append(f"  [+] {h}: {resp.headers[h][:80]}")
        else:
            missing.append(f"  [-] FALTANDO {h} ({desc})")

    score = len(present)
    grade = "A" if score == 6 else "B" if score >= 4 else "C" if score >= 2 else "D"
    out = [f"[Headers] {resp.url} (HTTP {resp.status_code}) — score {score}/{len(wanted)} (nota {grade})"]
    out += present + missing
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Tool extra 7 — Resolução de DNS / IP
# ---------------------------------------------------------------------------
def resolve_dns(domain: str) -> str:
    """Resolve um domínio para seus endereços IP (IPv4 e IPv6) e faz DNS reverso.

    Usa o resolvedor do sistema (socket.getaddrinfo) para obter todos os IPs
    (registros A e AAAA) e tenta o PTR reverso do primeiro IPv4.

    Args:
        domain: Domínio a resolver, ex: "github.com".

    Returns:
        Texto com IPs IPv4/IPv6 resolvidos e o hostname reverso.
    """
    domain = _clean_domain(domain)
    if not domain:
        return "[DNS] Informe um domínio."

    try:
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror as e:
        return f"[DNS] Não foi possível resolver '{domain}': {e}"

    ipv4, ipv6 = set(), set()
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            ipv4.add(sockaddr[0])
        elif family == socket.AF_INET6:
            ipv6.add(sockaddr[0])

    out = [f"[DNS] Resolução de '{domain}':"]
    out.append("  IPv4 (A):")
    out += [f"    - {ip}" for ip in sorted(ipv4)] or ["    (nenhum)"]
    out.append("  IPv6 (AAAA):")
    out += [f"    - {ip}" for ip in sorted(ipv6)] or ["    (nenhum)"]

    # DNS reverso (PTR) do primeiro IPv4.
    if ipv4:
        first = sorted(ipv4)[0]
        try:
            ptr = socket.gethostbyaddr(first)[0]
            out.append(f"  Reverso (PTR) de {first}: {ptr}")
        except (socket.herror, socket.gaierror):
            out.append(f"  Reverso (PTR) de {first}: (sem registro)")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Tool 8 — Fuzzing de diretórios/arquivos web (content discovery)
# ---------------------------------------------------------------------------
# Wordlist embutida de caminhos sensíveis comuns (estilo gobuster/ffuf).
# Embutida no código para funcionar em qualquer ambiente (Docker incluso).
WEB_FUZZ_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
    "robots.txt", "sitemap.xml", ".git/config", ".git/HEAD", ".env", ".htaccess",
    "backup", "backup.zip", "backup.sql", "db.sql", "dump.sql", "config.php",
    "config", "configuration", "phpinfo.php", "info.php", "test", "test.php",
    "api", "api/v1", "api/v2", "swagger", "swagger-ui", "graphql", "actuator",
    "actuator/health", "server-status", "status", "metrics", "debug",
    "uploads", "upload", "files", "tmp", "temp", "old", "dev", "staging",
    "console", "shell", "cmd", "phpmyadmin", "adminer.php", "license.txt",
    "readme.txt", "README.md", "CHANGELOG.md", ".well-known/security.txt",
]


def fuzz_web_paths(url: str) -> str:
    """Faz fuzzing de diretórios/arquivos web (content discovery) num site.

    Funciona como um mini gobuster/ffuf: para cada caminho de uma wordlist
    embutida de paths sensíveis comuns (admin, .git/config, .env, backups,
    api, phpmyadmin, etc.), faz uma requisição HTTP real e reporta os que
    NÃO retornam 404 — possíveis arquivos/diretórios expostos. As requisições
    rodam em paralelo (threads) para ser rápido. Detecta também "soft 404"
    (site que devolve 200 para qualquer caminho) para evitar falsos positivos.

    Uso ético: rode apenas em alvos próprios ou com autorização explícita.

    Args:
        url: Site alvo, ex: "exemplo.com" ou "https://exemplo.com".

    Returns:
        Texto com os caminhos descobertos (status code e tamanho da resposta).
    """
    url = url.strip()
    if not url:
        return "[Fuzz] Informe uma URL."
    if not url.startswith("http"):
        url = "https://" + url
    base = url.rstrip("/")

    sess = _session(retries=1)

    # Detecção de soft-404: pede um caminho aleatório improvável.
    soft404 = False
    try:
        probe = sess.get(f"{base}/zzq_nao_existe_404_{int(datetime.now().timestamp())}",
                         timeout=TIMEOUT, allow_redirects=False)
        if probe.status_code == 200:
            soft404 = True
    except requests.RequestException as e:
        return f"[Fuzz] Erro ao acessar {base}: {e}"

    rate_limited = [0]  # nº de respostas 429 (inconclusivas, não são "achados")

    def probe_path(path: str):
        full = f"{base}/{path}"
        try:
            r = sess.get(full, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            return None
        # 429 = rate-limit do servidor: inconclusivo, não conta como descoberta.
        if r.status_code == 429:
            rate_limited[0] += 1
            return None
        # Ignora 404 (e qualquer 200 se o site for soft-404).
        if r.status_code == 404:
            return None
        if soft404 and r.status_code == 200:
            return None
        return (r.status_code, len(r.content), full)

    found = []
    # Concorrência moderada: rápido sem disparar rate-limit agressivo.
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(probe_path, p): p for p in WEB_FUZZ_WORDLIST}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                found.append(res)

    header = f"[Fuzz] Content discovery em {base} ({len(WEB_FUZZ_WORDLIST)} paths testados)"
    if soft404:
        header += "\n  AVISO: site responde 200 para paths inexistentes (soft-404); 200 foi ignorado."
    if rate_limited[0]:
        header += f"\n  AVISO: {rate_limited[0]} requisição(ões) levaram 429 (rate-limit) e foram ignoradas."
    if not found:
        return header + "\n  Nenhum caminho interessante encontrado (todos 404 ou inacessíveis)."

    found.sort(key=lambda x: (x[0], x[2]))
    lines = "\n".join(
        f"  [{code}] {full}  ({size} bytes)" for code, size, full in found
    )
    return header + f"\n  {len(found)} caminho(s) encontrado(s):\n{lines}"


# ---------------------------------------------------------------------------
# Tool 9 — Fuzzing/brute-force ativo de subdomínios via DNS
# ---------------------------------------------------------------------------
# Wordlist embutida de subdomínios comuns.
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "dns", "vpn", "remote", "api", "dev", "staging", "stage", "test", "qa",
    "uat", "admin", "portal", "app", "apps", "blog", "shop", "store", "cdn",
    "static", "assets", "img", "images", "media", "cloud", "git", "gitlab",
    "jenkins", "ci", "jira", "confluence", "wiki", "docs", "support", "help",
    "status", "monitor", "grafana", "kibana", "db", "database", "mysql",
    "postgres", "redis", "internal", "intranet", "secure", "login", "auth",
    "sso", "m", "mobile", "beta", "demo", "sandbox", "old", "new", "backup",
]


def fuzz_subdomains_dns(domain: str) -> str:
    """Faz fuzzing/brute-force ATIVO de subdomínios resolvendo nomes via DNS.

    Complementa o crt.sh (que é passivo, via Certificate Transparency): aqui
    testamos uma wordlist embutida de subdomínios comuns (www, mail, vpn, dev,
    staging, api, grafana, etc.), tentando resolver cada um via DNS em paralelo.
    Reporta os subdomínios que resolvem e seus IPs — descobrindo hosts que
    podem não aparecer em certificados.

    Uso ético: rode apenas em alvos próprios ou com autorização explícita.

    Args:
        domain: Domínio base, ex: "tesla.com".

    Returns:
        Texto com os subdomínios que resolveram e seus IPs.
    """
    domain = _clean_domain(domain)
    if not domain or "." not in domain:
        return f"[SubFuzz] Domínio inválido: '{domain}'."

    def resolve(sub: str):
        fqdn = f"{sub}.{domain}"
        try:
            _, _, ips = socket.gethostbyname_ex(fqdn)
            return (fqdn, ips)
        except (socket.gaierror, socket.herror, UnicodeError):
            return None

    found = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(resolve, s): s for s in SUBDOMAIN_WORDLIST}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                found.append(res)

    header = f"[SubFuzz] Brute-force DNS em *.{domain} ({len(SUBDOMAIN_WORDLIST)} nomes testados)"
    if not found:
        return header + "\n  Nenhum subdomínio da wordlist resolveu."

    found.sort(key=lambda x: x[0])
    lines = "\n".join(f"  [+] {fqdn:<30} -> {', '.join(ips)}" for fqdn, ips in found)
    return header + f"\n  {len(found)} subdomínio(s) ativo(s):\n{lines}"


# ---------------------------------------------------------------------------
# Tool 10 — Consulta completa de registros DNS (dnspython)
# ---------------------------------------------------------------------------
def query_dns_records(domain: str) -> str:
    """Consulta vários tipos de registro DNS de um domínio (A, AAAA, MX, NS,
    TXT, CNAME, SOA) usando a biblioteca dnspython.

    Vai além do resolve_dns (que só faz A/AAAA/PTR): traz servidores de e-mail
    (MX), name servers (NS), registros TXT (SPF/DKIM/verificações) e SOA — úteis
    em reconhecimento de infraestrutura.

    Args:
        domain: Domínio a consultar, ex: "github.com".

    Returns:
        Texto com os registros DNS encontrados, agrupados por tipo.
    """
    import dns.resolver  # dnspython

    domain = _clean_domain(domain)
    if not domain or "." not in domain:
        return f"[DNS-Rec] Domínio inválido: '{domain}'."

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    out = [f"[DNS-Rec] Registros DNS de '{domain}':"]
    any_found = False
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            answers = resolver.resolve(domain, rtype)
            values = [r.to_text() for r in answers]
            any_found = True
            out.append(f"  {rtype}:")
            out += [f"    - {v}" for v in values]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            out.append(f"  {rtype}: (erro: {e})")
        except Exception:
            continue

    if not any_found:
        return f"[DNS-Rec] Nenhum registro DNS encontrado para '{domain}'."
    return "\n".join(out)


# Lista exportada para o agente registrar todas as tools de uma vez.
ALL_TOOLS = [
    search_subdomains_crt,
    verify_username_presence,
    get_whois_info,
    check_wayback_machine,
    analyze_file_steganography,
    analyze_http_security_headers,
    resolve_dns,
    fuzz_web_paths,
    fuzz_subdomains_dns,
    query_dns_records,
]
