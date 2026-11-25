# ARQUIVO PROPOSITALMENTE INSEGURO - fixture de demonstracao do ConfigGuard.
FROM python:3.12

ENV APP_ENV=development \
    DEBUG=True

WORKDIR /app
COPY . /app

RUN apt-get update && apt-get install -y openssh-server && \
    pip install -r requirements.txt && \
    chmod -R 777 /app

EXPOSE 22 5432 8000

USER root
CMD ["python", "app.py"]
