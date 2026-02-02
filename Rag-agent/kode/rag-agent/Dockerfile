FROM python:3.11-slim

# Sæt arbejdsmappe
WORKDIR /app

# Kopier requirements og installer dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopier backend applikationskode
COPY App/backend/ ./backend/

# Opret prompts mappe (vil blive overskrevet af volume)
RUN mkdir -p /app/prompts /app/chroma_collections

# Eksponer port
EXPOSE 8000

# Start kommando - opdateret til ny struktur
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
