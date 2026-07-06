FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git \
 && curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
 && curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks \
 && curl -sSfL https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 -o /usr/local/bin/hadolint \
 && chmod +x /usr/local/bin/hadolint \
 && curl -sSfL https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv0.22.2/cargo-audit-x86_64-unknown-linux-musl-v0.22.2.tgz \
    | tar -xz -C /tmp \
 && cp "$(find /tmp -type f -name cargo-audit | head -n1)" /usr/local/bin/cargo-audit \
 && chmod +x /usr/local/bin/cargo-audit \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask semgrep bandit pip-audit
# prechauffe: telecharge et cache les regles "auto" dans l'image (1er scan rapide)
RUN mkdir -p /warm && echo "eval(x)" > /warm/t.py \
 && semgrep scan --config auto --quiet /warm/t.py >/dev/null 2>&1 || true
COPY app.py app_api.py /app/
COPY stv/ /app/stv/
COPY templates/ /app/templates/
WORKDIR /app
EXPOSE 5000
CMD ["python", "app.py"]
