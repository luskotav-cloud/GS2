"""
tools.py — Ferramentas (tools) de OSINT e Forense para o agente de IA.

Cada função abaixo é uma tool real, registrada no agente Agno.
Todas executam ações reais (requisições HTTP, leitura binária de arquivos,
consultas WHOIS), nunca retornam respostas fixas/simuladas.

Tema do agente: Reconhecimento e Forense Digital (OSINT Security Agent).
"""

import json
import socket
import struct
from datetime import datetime

import requests

# User-Agent comum para evitar bloqueios triviais de algumas plataformas.
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}
TIMEOUT = 15


# ---------------------------------------------------------------------------
# Tool 1 — Enumeração de subdomínios via Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------
def search_subdomains_crt(domain: str) -> str:
    """Enumera subdomínios de um domínio consultando logs de Certificate
    Transparency através da API pública do crt.sh.

    Faz uma requisição HTTP para https://crt.sh/?q=%25.<dominio>&output=json,
    extrai todos os 'name_value' dos certificados emitidos e retorna a lista
    de subdomínios ÚNICOS encontrados.

    Args:
        domain: Domínio alvo, ex: "tesla.com" (sem http:// e sem www).

    Returns:
        Texto com a contagem e a lista de subdomínios únicos descobertos.
    """
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").strip("/")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code != 200:
            return f"[crt.sh] Falha na consulta. Status code: {resp.status_code}"
        data = resp.json()
    except json.JSONDecodeError:
        return "[crt.sh] Resposta vazia ou inválida (nenhum certificado encontrado)."
    except requests.RequestException as e:
        return f"[crt.sh] Erro de rede: {e}"

    subdomains = set()
    for entry in data:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain) and name:
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

    Faz requisições HTTP reais e analisa o status code (200 = existe,
    404 = não existe) nas plataformas GitHub, Reddit, TryHackMe e Instagram.

    Args:
        username: Nome de usuário a investigar, ex: "torvalds".

    Returns:
        Texto indicando em quais plataformas o username foi encontrado.
    """
    username = username.strip()
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "TryHackMe": f"https://tryhackme.com/p/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
    }

    results = []
    for name, url in platforms.items():
        try:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
            code = resp.status_code
            if code == 200:
                results.append(f"  [+] ENCONTRADO  {name:<10} -> {url} (200)")
            elif code == 404:
                results.append(f"  [-] livre       {name:<10} (404)")
            else:
                results.append(f"  [?] incerto     {name:<10} (status {code})")
        except requests.RequestException as e:
            results.append(f"  [!] erro        {name:<10} ({e})")

    return f"Verificação do username '{username}':\n" + "\n".join(results)


# ---------------------------------------------------------------------------
# Tool 3 — Consulta WHOIS de domínio
# ---------------------------------------------------------------------------
def get_whois_info(domain: str) -> str:
    """Consulta os dados de registro WHOIS de um domínio.

    Usa a biblioteca python-whois para obter data de criação, registrar e
    e-mails de contato do domínio informado.

    Args:
        domain: Domínio alvo, ex: "google.com".

    Returns:
        Texto com Creation Date, Registrar e Emails do registro.
    """
    import whois  # python-whois

    domain = domain.strip().lower().replace("https://", "").replace("http://", "").strip("/")
    try:
        w = whois.whois(domain)
    except Exception as e:
        return f"[WHOIS] Erro ao consultar {domain}: {e}"

    def fmt(value):
        if isinstance(value, list):
            return ", ".join(str(v) for v in value)
        return str(value) if value else "N/A"

    creation = fmt(w.creation_date)
    expiration = fmt(w.expiration_date)
    registrar = fmt(w.registrar)
    emails = fmt(w.emails)
    name_servers = fmt(w.name_servers)

    return (
        f"[WHOIS] Registro de {domain}:\n"
        f"  Creation Date : {creation}\n"
        f"  Expiration    : {expiration}\n"
        f"  Registrar     : {registrar}\n"
        f"  Emails        : {emails}\n"
        f"  Name Servers  : {name_servers}"
    )


# ---------------------------------------------------------------------------
# Tool 4 — Verificação de snapshots no Wayback Machine
# ---------------------------------------------------------------------------
def check_wayback_machine(url: str) -> str:
    """Verifica se um site possui snapshots arquivados no Internet Archive.

    Consulta a API pública http://archive.org/wayback/available?url=<url>
    para descobrir se o site suspeito foi arquivado e retorna a URL do
    snapshot disponível mais próximo.

    Args:
        url: Site/URL a verificar, ex: "exemplo-suspeito.com".

    Returns:
        Texto com o snapshot encontrado (URL e timestamp) ou aviso de ausência.
    """
    target = url.strip()
    api = f"http://archive.org/wayback/available?url={target}"
    try:
        resp = requests.get(api, headers=HEADERS, timeout=TIMEOUT)
        data = resp.json()
    except requests.RequestException as e:
        return f"[Wayback] Erro de rede: {e}"
    except json.JSONDecodeError:
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
# Assinaturas (Magic Bytes) de formatos comuns que podem estar embutidos.
MAGIC_SIGNATURES = {
    b"\x50\x4b\x03\x04": "Arquivo ZIP/Office/APK (PK..)",
    b"\x52\x61\x72\x21\x1a\x07": "Arquivo RAR",
    b"\x25\x50\x44\x46": "Documento PDF (%PDF)",
    b"\x4d\x5a": "Executável Windows (MZ / PE)",
    b"\x7f\x45\x4c\x46": "Executável Linux (ELF)",
    b"\x1f\x8b\x08": "Arquivo GZIP",
    b"\x37\x7a\xbc\xaf\x27\x1c": "Arquivo 7-Zip",
    b"\x42\x5a\x68": "Arquivo BZIP2",
    b"\x49\x44\x33": "Áudio MP3 (ID3)",
    b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a": "Imagem PNG",
    b"\xff\xd8\xff": "Imagem JPEG",
    b"\x47\x49\x46\x38": "Imagem GIF",
}


def analyze_file_steganography(filepath: str) -> str:
    """Analisa um arquivo em busca de outros arquivos ocultos/embutidos (esteganografia).

    Funciona como um mini-Binwalk em Python puro: abre o arquivo em modo
    binário e varre todo o conteúdo procurando assinaturas hexadecimais
    (Magic Bytes) de formatos conhecidos (ZIP, RAR, PDF, executáveis MZ/ELF,
    etc.). Ignora a assinatura legítima do início do arquivo e reporta apenas
    arquivos embutidos em offsets posteriores.

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

    findings = []
    for sig, desc in MAGIC_SIGNATURES.items():
        start = 0
        while True:
            idx = content.find(sig, start)
            if idx == -1:
                break
            # offset 0 = assinatura legítima do próprio arquivo, não é "oculto"
            if idx != 0:
                findings.append((idx, desc, sig.hex()))
            start = idx + 1

    header_type = "desconhecido"
    for sig, desc in MAGIC_SIGNATURES.items():
        if content.startswith(sig):
            header_type = desc
            break

    summary = (
        f"[Forense] Análise de '{filepath}'\n"
        f"  Tamanho      : {len(content)} bytes\n"
        f"  Tipo (header): {header_type}\n"
    )

    if not findings:
        return summary + "  Resultado    : LIMPO — nenhum arquivo embutido detectado."

    findings.sort(key=lambda x: x[0])
    lines = "\n".join(
        f"    offset {off} (0x{off:X}): {desc} [magic {hx}]" for off, desc, hx in findings
    )
    return (
        summary
        + f"  Resultado    : SUSPEITO — {len(findings)} arquivo(s) embutido(s) detectado(s):\n"
        + lines
    )


# ---------------------------------------------------------------------------
# Tool extra 6 — Análise de cabeçalhos de segurança HTTP
# ---------------------------------------------------------------------------
def analyze_http_security_headers(url: str) -> str:
    """Analisa os cabeçalhos de segurança HTTP de um site.

    Faz uma requisição real e verifica a presença de cabeçalhos de segurança
    importantes (HSTS, CSP, X-Frame-Options, etc.), apontando os que faltam.

    Args:
        url: Site a analisar, ex: "github.com" ou "https://github.com".

    Returns:
        Texto com os cabeçalhos de segurança presentes e ausentes.
    """
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
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
    out = [f"[Headers] {url} (HTTP {resp.status_code}) — score {score}/{len(wanted)}"]
    out += present + missing
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Tool extra 7 — Resolução de DNS / IP
# ---------------------------------------------------------------------------
def resolve_dns(domain: str) -> str:
    """Resolve um domínio para seus endereços IP (registros A).

    Usa o resolvedor de DNS do sistema (socket) para obter todos os IPs
    associados ao domínio e o hostname canônico.

    Args:
        domain: Domínio a resolver, ex: "github.com".

    Returns:
        Texto com o hostname canônico e a lista de IPs resolvidos.
    """
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").strip("/")
    try:
        hostname, aliases, ips = socket.gethostbyname_ex(domain)
    except socket.gaierror as e:
        return f"[DNS] Não foi possível resolver '{domain}': {e}"

    alias_txt = ", ".join(aliases) if aliases else "nenhum"
    ip_txt = "\n".join(f"  - {ip}" for ip in ips)
    return (
        f"[DNS] Resolução de '{domain}':\n"
        f"  Hostname canônico: {hostname}\n"
        f"  Aliases          : {alias_txt}\n"
        f"  IPs:\n{ip_txt}"
    )


# Lista exportada para o agente registrar todas as tools de uma vez.
ALL_TOOLS = [
    search_subdomains_crt,
    verify_username_presence,
    get_whois_info,
    check_wayback_machine,
    analyze_file_steganography,
    analyze_http_security_headers,
    resolve_dns,
]
