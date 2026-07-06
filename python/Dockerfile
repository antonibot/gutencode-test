FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Postgres / Supabase? uncomment (see .env.example: DATABASE_URL + SECURE_DELETE_ACK=1):
# RUN pip install --no-cache-dir 'psycopg[binary]>=3.2,<4'
COPY . .
RUN useradd --create-home app && mkdir -p /data && chown app:app /data
USER app
ENV PORT=8080 DATABASE_PATH=/data/app.db
EXPOSE 8080
VOLUME /data
# uvicorn owns the bind: 0.0.0.0 for containers; PORT is honored from the environment.
CMD ["sh", "-c", "uvicorn app_pkg.app:app --host 0.0.0.0 --port ${PORT:-8080} --timeout-keep-alive 10"]
