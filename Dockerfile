# Dockerfile — OSINT Recon Agent (pontuação extra: containerização)
#
# A imagem sobe a interface web (Flask) por padrão. O modelo padrão é a
# Gemini API (cloud), então o container NÃO precisa de GPU nem do Ollama.
#
# A chave da API NÃO é embutida na imagem (o .env fica fora do build context
# via .dockerignore). Ela é passada em tempo de execução com --env-file .env.
#
# Build:
#   docker build -t osint-agent .
#
# Rodar a interface web (Windows / Docker Desktop):
#   docker run --rm -p 5000:5000 --env-file .env osint-agent
#   -> abra http://localhost:5000
#
# Rodar a CLI interativa:
#   docker run --rm -it --env-file .env osint-agent python main.py
#
# Fallback para Ollama local (no host Windows), em vez de Gemini:
#   docker run --rm -p 5000:5000 ^
#     -e MODEL_PROVIDER=ollama ^
#     -e OLLAMA_HOST=http://host.docker.internal:11434 ^
#     osint-agent

FROM python:3.13-slim

WORKDIR /app

# Certificados para as requisições HTTPS (crt.sh, archive.org, Gemini, etc.).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Dentro do container o Flask precisa escutar em 0.0.0.0 para expor a porta.
ENV FLASK_HOST=0.0.0.0
ENV FLASK_PORT=5000

EXPOSE 5000

# Padrão: interface web. Sobrescreva com `python main.py` para a CLI.
CMD ["python", "server.py"]
