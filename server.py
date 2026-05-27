"""
server.py — Servidor Flask (API + interface web Vue) do OSINT Recon Agent.

Pontuação extra: interface web simples com Flask.
Front-end em Vue 3 (via CDN, sem build) servido pelo template index.html.

Rotas:
    GET  /            -> página da interface (templates/index.html)
    POST /api/chat    -> {"message": "...", "session_id": "..."} -> resposta do agente
    GET  /api/tools   -> lista as tools disponíveis
    POST /api/reset   -> {"session_id": "..."} -> reinicia a sessão

Uso:
    python server.py
"""

import os

from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from agent import build_agent, AGENT_NAME, MODEL_LABEL
from tools import ALL_TOOLS

load_dotenv()

app = Flask(__name__)
CORS(app)

# Cache de agentes por session_id (mantém histórico em memória + SQLite).
_agents: dict[str, object] = {}


def get_agent(session_id: str):
    if session_id not in _agents:
        _agents[session_id] = build_agent(session_id=session_id, user_id="web-user")
    return _agents[session_id]


@app.route("/")
def index():
    return render_template("index.html", agent_name=AGENT_NAME, model=MODEL_LABEL)


@app.route("/api/tools")
def api_tools():
    tools = []
    for fn in ALL_TOOLS:
        doc = (fn.__doc__ or "").strip().splitlines()[0]
        tools.append({"name": fn.__name__, "description": doc})
    return jsonify({"agent": AGENT_NAME, "model": MODEL_LABEL, "tools": tools})


@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    session_id = (data.get("session_id") or "web-default").strip()

    if not message:
        return jsonify({"error": "Mensagem vazia."}), 400

    try:
        agent = get_agent(session_id)
        result = agent.run(message)
        return jsonify({"response": result.content, "session_id": session_id})
    except Exception as e:
        return jsonify({"error": f"Falha ao executar o agente: {e}"}), 500


@app.route("/api/reset", methods=["POST"])
def api_reset():
    data = request.get_json(silent=True) or {}
    session_id = (data.get("session_id") or "web-default").strip()
    _agents.pop(session_id, None)
    return jsonify({"status": "ok", "message": f"Sessão {session_id} reiniciada."})


if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", "5000"))
    print(f"Servidor web em http://{host}:{port}  (modelo: {MODEL_LABEL})")
    app.run(host=host, port=port, debug=True, use_reloader=False)
