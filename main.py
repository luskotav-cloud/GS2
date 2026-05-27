"""
main.py — Interface de linha de comando (CLI) do OSINT Recon Agent.

Uso:
    python main.py

Conversa interativa no terminal (estilo chat). O agente mantém o contexto
da sessão entre as perguntas via SQLite. Comandos especiais:
    /new   -> inicia uma nova sessão (limpa o contexto)
    /help  -> mostra as tools disponíveis
    /sair  -> encerra (também /exit, /quit)
"""

import sys
import uuid

from agent import build_agent, AGENT_NAME, MODEL_LABEL, MODEL_PROVIDER
from tools import ALL_TOOLS

BANNER = r"""
============================================================
   OSINT RECON AGENT  —  GS Coding for Security
   Modelo: {model} ({provider})   |   Framework: Agno
============================================================
 Faça perguntas de reconhecimento/forense em linguagem natural.
 Ex: "enumere os subdominios de tesla.com"
     "o usuario torvalds existe em quais plataformas?"
     "analise o arquivo suspeito.png"
 Comandos: /new (nova sessao)  /help (tools)  /sair (encerrar)
============================================================
""".format(model=MODEL_LABEL, provider=MODEL_PROVIDER)


def print_help() -> None:
    print("\nTools disponíveis no agente:")
    for fn in ALL_TOOLS:
        doc = (fn.__doc__ or "").strip().splitlines()[0]
        print(f"  - {fn.__name__}: {doc}")
    print()


def main() -> None:
    print(BANNER)
    session_id = str(uuid.uuid4())
    agent = build_agent(session_id=session_id, user_id="cli-user")
    print(f"[sessão: {session_id[:8]}]  Agente '{AGENT_NAME}' pronto.\n")

    while True:
        try:
            user_input = input("voce > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nEncerrando. Até logo!")
            break

        if not user_input:
            continue

        cmd = user_input.lower()
        if cmd in ("/sair", "/exit", "/quit"):
            print("Encerrando. Até logo!")
            break
        if cmd == "/help":
            print_help()
            continue
        if cmd == "/new":
            session_id = str(uuid.uuid4())
            agent = build_agent(session_id=session_id, user_id="cli-user")
            print(f"[nova sessão: {session_id[:8]}]\n")
            continue

        # Resposta em streaming (renderização estilo chat com markdown).
        print()
        agent.print_response(user_input, stream=True)
        print()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[ERRO FATAL] {e}", file=sys.stderr)
        sys.exit(1)
