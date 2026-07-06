FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
 && curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
 && curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask semgrep
# prechauffe: telecharge et cache les regles "auto" dans l'image (1er scan rapide)
RUN mkdir -p /warm && echo "eval(x)" > /warm/t.py \
 && semgrep scan --config auto --quiet /warm/t.py >/dev/null 2>&1 || true
COPY app.py app_api.py /app/
COPY stv/ /app/stv/
COPY templates/ /app/templates/
WORKDIR /app
EXPOSE 5000
CMD ["python", "app.py"]
