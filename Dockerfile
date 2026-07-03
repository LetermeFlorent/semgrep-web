FROM python:3.12-slim
RUN pip install --no-cache-dir flask semgrep
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 5000
CMD ["python", "app.py"]
