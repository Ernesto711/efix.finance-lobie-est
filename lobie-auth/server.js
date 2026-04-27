/**
 * ═══════════════════════════════════════════════════════════════
 *  Lobie Auth Service
 *  OTP por email + JWT issuance para a plataforma Lobie
 *
 *  Endpoints:
 *    POST /auth/send-otp     body {email}        → {success}
 *    POST /auth/verify-otp   body {email, code}  → {success, token, user}
 *    GET  /health            → {ok, ts}
 *    GET  /                  → service info
 *
 *  Whitelist via env:
 *    ALLOWED_EMAILS  (csv)  emails individuais autorizados
 *    ALLOWED_DOMAINS (csv)  domínios de email autorizados
 *
 *  Email transport (auto-detect):
 *    1. RESEND_API_KEY → Resend
 *    2. SMTP_USER + SMTP_PASS → nodemailer (Gmail por default)
 *    3. Nenhum → console.log fallback (dev)
 * ═══════════════════════════════════════════════════════════════
 */

import Fastify from 'fastify';
import cors from '@fastify/cors';
import jwt from 'jsonwebtoken';

const app = Fastify({
  logger: { level: process.env.LOG_LEVEL || 'info' }
});

await app.register(cors, {
  origin: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: false,
});

// ── Whitelist (env-driven, com defaults sensatos) ──────────────────
const DEFAULT_DOMAINS = ['lobie.com.br', 'efix.finance', 'hausbank.com.br', 'patrimar.com.br'];
const DEFAULT_EMAILS = [
  'ernesto.otero@hausbank.com.br',
  'ernesto.otero@lobie.com.br',
  'ernesto.otero@efix.finance',
  'ernesto@efix.finance',
  'mariano@lobie.com.br',
  'briane@lobie.com.br',
  'bruno@lobie.com.br',
  'milene@lobie.com.br',
];

const ALLOWED_DOMAINS = (process.env.ALLOWED_DOMAINS || DEFAULT_DOMAINS.join(','))
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const ALLOWED_EMAILS = (process.env.ALLOWED_EMAILS || DEFAULT_EMAILS.join(','))
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

function isEmailAllowed(email) {
  const e = email.trim().toLowerCase();
  if (ALLOWED_EMAILS.includes(e)) return true;
  const dom = e.split('@')[1] || '';
  return ALLOWED_DOMAINS.includes(dom);
}

// ── OTP store (in-memory; suficiente para 1 instância Railway) ─────
const otpStore = new Map();
const OTP_TTL_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Cleanup stale entries a cada 5 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of otpStore.entries()) {
    if (v.expires < now) otpStore.delete(k);
  }
}, 5 * 60 * 1000).unref();

// ── Email transport (auto-detect) ──────────────────────────────────
let resendClient = null;
let smtpTransporter = null;

if (process.env.RESEND_API_KEY) {
  const { Resend } = await import('resend');
  resendClient = new Resend(process.env.RESEND_API_KEY);
  app.log.info('Email transport: Resend');
} else if (process.env.SMTP_USER && process.env.SMTP_PASS) {
  const nodemailer = (await import('nodemailer')).default;
  smtpTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '465'),
    secure: (process.env.SMTP_SECURE || 'true') !== 'false',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  app.log.info(`Email transport: SMTP via ${process.env.SMTP_HOST || 'smtp.gmail.com'}`);
} else {
  app.log.warn('Email transport: NONE (codes will print to console)');
}

const MAIL_FROM = process.env.MAIL_FROM
  || (process.env.SMTP_USER ? `Lobie <${process.env.SMTP_USER}>` : 'Lobie <noreply@lobie.com.br>');

function emailHtml(code) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:24px;background:#f8f8f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <div style="max-width:480px;margin:0 auto;background:#fff;border-radius:14px;padding:40px 32px;box-shadow:0 4px 20px rgba(0,0,0,.05)">
    <div style="font-size:11px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#0BC0ED;margin-bottom:6px">LOBIE</div>
    <h1 style="font-size:24px;margin:0 0 14px;color:#0a0a0a;font-weight:700;letter-spacing:-.3px">Seu código de acesso</h1>
    <p style="font-size:14px;color:#555;line-height:1.65;margin:0 0 22px">Use o código abaixo para entrar na plataforma Lobie. Ele expira em 10 minutos.</p>
    <div style="background:linear-gradient(135deg,rgba(11,192,237,.10) 0%,#f5f7f9 100%);border:1px solid rgba(11,192,237,.30);border-radius:12px;padding:28px 20px;text-align:center;margin:0 0 22px">
      <div style="font-family:'Courier New',monospace;font-size:36px;letter-spacing:10px;font-weight:700;color:#0BC0ED">${code}</div>
    </div>
    <p style="font-size:12px;color:#777;line-height:1.6;margin:0 0 8px"><strong>Não solicitou?</strong> Pode ignorar este email — alguém pode ter digitado seu endereço por engano.</p>
    <hr style="border:none;border-top:1px solid #eee;margin:28px 0 16px">
    <p style="font-size:10px;color:#999;line-height:1.6;margin:0">Lobie · Plataforma de Estudos de Rentabilidade STR<br>contato@lobie.com.br</p>
  </div>
</body></html>`;
}

async function sendOTPEmail(email, code) {
  const subject = `Código Lobie: ${code}`;
  const html = emailHtml(code);

  if (resendClient) {
    return resendClient.emails.send({ from: MAIL_FROM, to: email, subject, html });
  }
  if (smtpTransporter) {
    return smtpTransporter.sendMail({ from: MAIL_FROM, to: email, subject, html });
  }
  app.log.warn(`[DEV·NO-EMAIL] OTP for ${email}: ${code}`);
}

// ── Routes ─────────────────────────────────────────────────────────
app.post('/auth/send-otp', async (req, reply) => {
  const { email } = req.body || {};
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return reply.code(400).send({ error: 'Email inválido' });
  }
  const e = email.trim().toLowerCase();
  if (!isEmailAllowed(e)) {
    app.log.info({ email: e }, 'unauthorized email attempt');
    return reply.code(403).send({ error: 'Email não autorizado para esta plataforma. Solicite acesso a contato@lobie.com.br.' });
  }
  const code = generateOTP();
  otpStore.set(e, { code, expires: Date.now() + OTP_TTL_MS, attempts: 0 });
  try {
    await sendOTPEmail(e, code);
    app.log.info({ email: e }, 'otp dispatched');
  } catch (err) {
    app.log.error({ err: err.message, email: e }, 'send email failed');
    return reply.code(502).send({ error: 'Falha ao enviar email. Tente novamente.' });
  }
  return { success: true, message: 'Código enviado por email. Verifique sua caixa de entrada (e spam).' };
});

app.post('/auth/verify-otp', async (req, reply) => {
  const { email, code } = req.body || {};
  if (!email || !code) {
    return reply.code(400).send({ error: 'Email e código obrigatórios' });
  }
  const e = email.trim().toLowerCase();
  const c = String(code).trim();
  const entry = otpStore.get(e);

  if (!entry) {
    return reply.code(400).send({ error: 'Código não encontrado. Solicite novamente.' });
  }
  if (entry.expires < Date.now()) {
    otpStore.delete(e);
    return reply.code(400).send({ error: 'Código expirado. Solicite novamente.' });
  }
  if (entry.attempts >= MAX_ATTEMPTS) {
    otpStore.delete(e);
    return reply.code(429).send({ error: 'Muitas tentativas. Solicite um novo código.' });
  }
  if (entry.code !== c) {
    entry.attempts++;
    return reply.code(400).send({ error: `Código inválido (${entry.attempts}/${MAX_ATTEMPTS} tentativas).` });
  }

  otpStore.delete(e);

  const secret = process.env.JWT_SECRET;
  if (!secret) {
    app.log.error('JWT_SECRET not set');
    return reply.code(500).send({ error: 'Servidor mal configurado. Contate suporte.' });
  }
  const token = jwt.sign({ email: e, iss: 'lobie-auth' }, secret, { expiresIn: '24h' });
  app.log.info({ email: e }, 'login success');
  return {
    success: true,
    token,
    user: { email: e },
  };
});

app.get('/health', async () => ({ ok: true, ts: Date.now(), service: 'lobie-auth' }));

app.get('/', async () => ({
  service: 'lobie-auth',
  version: '1.0.0',
  endpoints: ['POST /auth/send-otp', 'POST /auth/verify-otp', 'GET /health'],
  whitelisted_domains: ALLOWED_DOMAINS.length,
  whitelisted_emails: ALLOWED_EMAILS.length,
  email_transport: resendClient ? 'resend' : (smtpTransporter ? 'smtp' : 'none'),
}));

// ── Start ──────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '3000');
const HOST = process.env.HOST || '0.0.0.0';

try {
  await app.listen({ port: PORT, host: HOST });
  app.log.info(`lobie-auth listening on http://${HOST}:${PORT}`);
  app.log.info(`whitelisted: ${ALLOWED_DOMAINS.length} domains, ${ALLOWED_EMAILS.length} emails`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
