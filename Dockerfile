FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "-c", "import os,uvicorn; uvicorn.run('api:app', host='0.0.0.0', port=int(os.environ.get('PORT', 8000)))"]
