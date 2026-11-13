# ai-analyst: le alertas do Wazuh, analisa com LLM local (Ollama), guarda
# historico (SQLite + embeddings) e gera recomendacoes de prevencao.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 TZ=America/Sao_Paulo
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY analyst ./analyst
CMD ["python", "-m", "analyst.main"]
