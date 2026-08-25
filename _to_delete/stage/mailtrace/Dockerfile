FROM python:3.12-slim

# WeasyPrint (M10) needs cairo/pango. Everything else is pure Python.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libpq5 libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
        libgdk-pixbuf-2.0-0 libffi-dev curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
