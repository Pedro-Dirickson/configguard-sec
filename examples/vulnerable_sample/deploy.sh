#!/bin/sh
# ARQUIVO PROPOSITALMENTE INSEGURO - fixture de demonstracao do ConfigGuard.
# Os tokens abaixo sao ficticios (o JWT e o exemplo publico de jwt.io).
set -eu

API_URL="https://api.internal.example.com/v1/deploy"
SERVICE_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

curl -fsS -X POST "$API_URL" \
    -H "Authorization: Bearer 7tQx2Lp9Vm4Kz8Rw1Nb6Hc3Yd5Fj0Gs" \
    -d '{"service": "payments", "version": "1.4.2"}'

curl -fsS "$API_URL/status" -H "Authorization: Bearer $SERVICE_JWT"

chmod 777 /opt/payments/bin/*.sh
