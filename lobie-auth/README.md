# Lobie Auth Service

OTP por email + JWT para a plataforma Lobie.

## Endpoints

- `POST /auth/send-otp` body `{email}` → manda código de 6 dígitos
- `POST /auth/verify-otp` body `{email, code}` → retorna `{success, token, user}`
- `GET /health` → status check
- `GET /` → service info

## Whitelist

Email validado contra `ALLOWED_EMAILS` (csv) e `ALLOWED_DOMAINS` (csv).

**Defaults pré-cadastrados:**
- Domínios: `lobie.com.br`, `efix.finance`, `hausbank.com.br`, `patrimar.com.br`
- Emails individuais: `ernesto.otero@hausbank.com.br`, `ernesto.otero@lobie.com.br`, `ernesto.otero@efix.finance`, `mariano@lobie.com.br`, `briane@lobie.com.br`, `bruno@lobie.com.br`, `milene@lobie.com.br`

Override via env `ALLOWED_EMAILS=...` ou `ALLOWED_DOMAINS=...`.

## Email transport

Auto-detect via env:
1. `RESEND_API_KEY` → Resend
2. `SMTP_USER` + `SMTP_PASS` → nodemailer (Gmail por default)
3. Nenhum → console.log fallback (dev)

## Deploy no Railway (5 min)

```bash
# 1. Da raiz do repo:
cd lobie-auth
npm install  # local test (opcional)

# 2. Push pra GitHub (já no repo efix.finance-lobie-est)
cd ..
git push origin main

# 3. Na Railway:
#    - New Project → Deploy from GitHub repo
#    - Selecione: efix.finance-lobie-est
#    - Service Settings → Root Directory: lobie-auth
#    - Variables (ver .env.example):
#        JWT_SECRET=<openssl rand -base64 64>
#        SMTP_USER=ernesto.otero@lobie.com.br
#        SMTP_PASS=<app password do Gmail Lobie>
#        MAIL_FROM=Lobie <ernesto.otero@lobie.com.br>
#    - Deploy

# 4. Pegue a URL pública (ex: https://lobie-auth-production.up.railway.app)
#    e atualize lobie-est/index.html:
#    LOBIE_AUTH_BACKEND='<url>'
#    LOBIE_AUTH_ENABLED=true
```

## Local dev

```bash
cp .env.example .env
# preencha JWT_SECRET (qualquer string p/ dev)
# SMTP_USER + SMTP_PASS opcionais (sem eles, OTP printa no console)

npm install
npm run dev  # auto-reload via --watch
```

Test:
```bash
curl -X POST http://localhost:3000/auth/send-otp \
  -H 'Content-Type: application/json' \
  -d '{"email":"ernesto.otero@hausbank.com.br"}'
# → {"success":true,"message":"Código enviado por email..."}
# (sem SMTP, código printa no console do servidor)

curl -X POST http://localhost:3000/auth/verify-otp \
  -H 'Content-Type: application/json' \
  -d '{"email":"ernesto.otero@hausbank.com.br","code":"123456"}'
# → {"success":true,"token":"eyJ...","user":{...}}
```

## Adicionar novo email/domínio autorizado

**Opção 1 (sem redeploy):** mudar env var `ALLOWED_EMAILS` ou `ALLOWED_DOMAINS` no Railway → restart automático.

**Opção 2 (defaults):** editar `DEFAULT_DOMAINS` ou `DEFAULT_EMAILS` em `server.js` → commit + auto-deploy via Railway.

## Stack

- Node.js 20+ · Fastify 5
- jsonwebtoken (HS256, expira em 24h)
- nodemailer (SMTP) ou Resend
- In-memory OTP store (TTL 10min, max 5 tentativas)

Sem Postgres ainda — para volumes maiores, migrar `otpStore` Map para Redis ou Postgres.
