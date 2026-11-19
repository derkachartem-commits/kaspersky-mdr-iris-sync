FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
CMD ["uvicorn", "kdp_iris_sync.app:app", "--host", "127.0.0.1", "--port", "8088"]
