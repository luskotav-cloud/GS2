"""
agent.py — Fábrica do agente de IA usando o framework Agno.

Centraliza a criação do Agent para ser reutilizado tanto pela CLI (main.py)
quanto pelo servidor Flask (server.py). Lê todas as configurações do .env.
"""

import os

from dotenv import load_dotenv
from agno.agent import Agent
from agno.models.ollama import Ollama
from agno.db.sqlite import SqliteDb

from tools import ALL_TOOLS

load_dotenv()

# --- Configurações lidas do .env (com defaults seguros) --------------------
# Provider do modelo: "gemini" (cloud, rápido) ou "ollama" (local).
# Se MODEL_PROVIDER não for definido mas houver GEMINI_API_KEY, usa Gemini.
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-flash-latest")
MODEL_PROVIDER = os.getenv("MODEL_PROVIDER", "gemini" if GEMINI_API_KEY else "ollama").lower()

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DB_FILE = os.getenv("AGENT_DB_FILE", "agent_sessions.db")
AGENT_NAME = os.getenv("AGENT_NAME", "OSINT Recon Agent")
NUM_HISTORY_RUNS = int(os.getenv("NUM_HISTORY_RUNS", "5"))

# Nome do modelo efetivamente em uso (exibido na CLI / web).
MODEL_LABEL = GEMINI_MODEL if MODEL_PROVIDER == "gemini" else OLLAMA_MODEL


def _build_model():
    """Instancia o modelo conforme o provider configurado."""
    if MODEL_PROVIDER == "gemini":
        if not GEMINI_API_KEY:
            raise RuntimeError(
                "MODEL_PROVIDER=gemini, mas GEMINI_API_KEY não está definido no .env."
            )
        from agno.models.google import Gemini

        # thinking_budget=0 desliga o "raciocínio" do Gemini 2.5 (que às vezes
        # consome todo o orçamento de saída e devolve texto final vazio).
        return Gemini(id=GEMINI_MODEL, api_key=GEMINI_API_KEY, thinking_budget=0)

    # Ollama local. keep_alive mantém o modelo na RAM entre requisições.
    # temperature baixa = respostas mais determinísticas e diretas (menos "enrolação").
    return Ollama(
        id=OLLAMA_MODEL,
        host=OLLAMA_HOST,
        keep_alive="15m",
        options={"temperature": 0.2},
    )

INSTRUCTIONS = [
    "Você é um agente de OSINT e forense digital. Seja DIRETO e objetivo.",
    "Fluxo: interprete o pedido, escolha a tool certa, extraia o alvo (domínio/username/IP/URL/arquivo) e CHAME a tool imediatamente.",
    "NÃO escreva preâmbulos, nem explique o que vai fazer, nem descreva a tool antes de usá-la. Apenas chame.",
    "NÃO raciocine em voz alta nem mostre seu pensamento. Vá direto à ação.",
    "Depois que a tool retornar, apenas devolva o resultado dela com no máximo UMA frase curta de contexto. Nada de textos longos.",
    "Use SEMPRE as tools para dados reais — nunca invente nem simule resultados.",
    "Só pergunte o alvo se ele realmente não foi informado e não puder ser inferido do histórico da conversa.",
    "Uso ético: análise defensiva e investigação autorizada.",
]


def build_agent(session_id: str = "default", user_id: str | None = None) -> Agent:
    """Cria e retorna um Agent Agno configurado com Ollama, tools e persistência.

    Args:
        session_id: Identificador da sessão (mantém histórico entre perguntas).
        user_id: Identificador opcional do usuário.

    Returns:
        Instância pronta de agno.agent.Agent.
    """
    db = SqliteDb(db_file=DB_FILE)

    agent = Agent(
        name=AGENT_NAME,
        model=_build_model(),
        tools=ALL_TOOLS,
        db=db,
        session_id=session_id,
        user_id=user_id,
        add_history_to_context=True,
        num_history_runs=NUM_HISTORY_RUNS,
        add_datetime_to_context=True,
        markdown=True,
        instructions=INSTRUCTIONS,
    )
    return agent
