// index.js
// Countryside Hub Publisher — Node + Express
// Envia e-mail p/ fiscalização (admin) + boas-vindas ao vendedor (Zoho SMTP)

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const multer = require("multer");

// =========================
// Variáveis de Ambiente
// =========================
const {
  PORT = 3000,
  SITE_NAME = "Countryside Hub",

  // Mailbox Zoho que envia (remetente) + App Password
  ADMIN_EMAIL,
  ADMIN_EMAIL_PASSWORD,

  // Para onde vai a cópia de fiscalização (pode ser o mesmo do ADMIN_EMAIL)
  REVIEW_EMAIL,

  // Domínio permitido no CORS (ex.: https://countrysidehub.com)
  ALLOWED_ORIGIN,

  // Avançado (só mude se souber)
  ZOHO_SMTP_HOST = "smtppro.zoho.com",
  ZOHO_SMTP_PORT = "465",
  ZOHO_SMTP_SECURE = "true"
} = process.env;

if (!ADMIN_EMAIL || !ADMIN_EMAIL_PASSWORD) {
  console.error(
    "[ERRO] Defina ADMIN_EMAIL e ADMIN_EMAIL_PASSWORD (App Password do Zoho)."
  );
  process.exit(1);
}

// =========================
// App & Segurança
// =========================
const app = express();

// Helmet (sem X-Frame-Options:DENY)
app.use(
  helmet({
    crossOriginResourcePolicy: false,
    frameguard: false, // vamos controlar via CSP abaixo
  })
);

// Content-Security-Policy para permitir embed no Admin do Shopify
app.use((req, res, next) => {
  // frame-ancestors: quem pode embutir sua app em <iframe>
  // Inclui admin.shopify.com e *.myshopify.com
  const csp = [
    "frame-ancestors",
    "'self'",
    "https://admin.shopify.com",
    "https://*.myshopify.com",
  ].join(" ");

  res.setHeader("Content-Security-Policy", csp);
  // Garante que não haverá X-Frame-Options bloqueando
  res.removeHeader("X-Frame-Options");
  next();
});

// CORS (opcional)
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // health checks, curl, etc.
      if (!ALLOWED_ORIGIN) return cb(null, true);
      const allowed = origin === ALLOWED_ORIGIN || origin === ALLOWED_ORIGIN.replace(/\/$/, "");
      return cb(allowed ? null : new Error("Origin not allowed by CORS"), allowed);
    },
    credentials: false,
  })
);

// Body parsers
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

// Rate limit anti-abuso nas rotas /api/
app.use(
  "/api/",
  rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// =====================
// Upload (anexos)
// =====================
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 5 }, // 10MB, até 5 arquivos
});

// Aceitar tanto docs quanto docs[]
const uploadFields = upload.fields([
  { name: "docs", maxCount: 5 },
  { name: "docs[]", maxCount: 5 },
]);

// =====================
// Nodemailer (Zoho)
// =====================
const transporter = nodemailer.createTransport({
  host: ZOHO_SMTP_HOST,
  port: Number(ZOHO_SMTP_PORT),
  secure: String(ZOHO_SMTP_SECURE).toLowerCase() === "true", // true para 465 (SSL)
  auth: {
    user: ADMIN_EMAIL,
    pass: ADMIN_EMAIL_PASSWORD,
  },
  pool: true,
  connectionTimeout: 20000,
  socketTimeout: 20000,
  tls: {
    minVersion: "TLSv1.2",
    rejectUnauthorized: true,
  },
});

// Verificação SMTP na subida (log)
transporter
  .verify()
  .then(() => console.log("[OK] SMTP Zoho verificado."))
  .catch((err) =>
    console.error("[ERRO] Falha ao verificar SMTP Zoho:", err?.message || err)
  );

// =====================
// Helpers
// =====================
function sanitize(str = "") {
  return String(str ?? "").trim();
}

function money(v) {
  const n = Number(String(v).replace(/[^\d.,-]/g, "").replace(",", "."));
  return Number.isFinite(n) ? n.toFixed(2) : "";
}

function buildAdminHtml(payload, filesInfo) {
  const {
    nome_empresa,
    nome_completo,
    cpf_cnpj,
    email,
    telefone,
    cidade,
    estado,
    categoria,
    subcategoria,
    produto,
    preco,
    aceita_propostas,
    entrega,
    local,
    descricao,
    termos_aceitos,
    propostas,
  } = payload;

  const linhas = [
    `<p><b>Nome completo:</b> ${sanitize(nome_completo)}</p>`,
    `<p><b>Nome da empresa:</b> ${sanitize(nome_empresa || "(não informado)")}</p>`,
    `<p><b>CPF/CNPJ:</b> ${sanitize(cpf_cnpj)}</p>`,
    `<p><b>E-mail:</b> ${sanitize(email)}</p>`,
    `<p><b>Telefone:</b> ${sanitize(telefone)}</p>`,
    `<p><b>Cidade/UF:</b> ${sanitize(cidade)} / ${sanitize(estado)}</p>`,
    `<p><b>Categoria:</b> ${sanitize(categoria)}</p>`,
    `<p><b>Subcategoria:</b> ${sanitize(subcategoria || "(não informado)")}</p>`,
    `<p><b>Produto/Animal:</b> ${sanitize(produto || "(não informado)")}</p>`,
    `<p><b>Preço (R$):</b> ${money(preco)}</p>`,
    `<p><b>Aceita propostas:</b> ${sanitize(aceita_propostas || propostas || "(não informado)")}</p>`,
    `<p><b>Entrega/Coleta:</b> ${sanitize(entrega || "(não informado)")}</p>`,
    `<p><b>Local:</b> ${sanitize(local || "(não informado)")}</p>`,
    `<p><b>Descrição:</b><br>${(sanitize(descricao) || "(sem descrição)").replace(/\n/g, "<br>")}</p>`,
    `<p><b>Termos & Condições:</b> ${termos_aceitos ? "Aceitos" : "Não aceitos"}</p>`,
  ];

  if (filesInfo?.length) {
    linhas.push(
      `<p><b>Anexos:</b> ${filesInfo
        .map((f) => `${f.originalname} (${(f.size / 1024).toFixed(1)} KB)`)
        .join(", ")}</p>`
    );
  }

  return `
    <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#222">
      <h2>NOVO ANÚNCIO PUBLICADO (auto)</h2>
      ${linhas.join("\n")}
      <hr>
      <p style="font-size:12px;color:#666">
        E-mail gerado automaticamente pelo formulário de anúncio do ${SITE_NAME}.
      </p>
    </div>
  `;
}

function buildWelcomeHtml(payload) {
  const { nome_completo, produto, preco } = payload;
  return `
    <div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;color:#222;line-height:1.5">
      <h2>Bem-vindo(a) ao ${SITE_NAME}!</h2>
      <p>Olá ${sanitize(nome_completo) || "vendedor(a)"} 👋</p>
      <p>Seu anúncio <b>${sanitize(produto || "seu produto")}</b> foi publicado com sucesso${
        preco ? ` por <b>R$ ${money(preco)}</b>` : ""
      }.</p>
      <ul>
        <li>Responda rapidamente os interessados;</li>
        <li>Negocie com transparência (preço, entrega/coleta, prazos);</li>
        <li>Evite pagamentos fora dos canais combinados.</li>
      </ul>
      <p>Bons negócios! 🚀</p>
      <p>Equipe ${SITE_NAME}</p>
    </div>
  `;
}

// =====================
// Rotas de Health/Debug
// =====================
app.get("/", (_req, res) => {
  // Página simples (também útil no embed dentro do Admin)
  res.status(200).send(`
    <!doctype html>
    <html lang="pt-br">
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>${SITE_NAME} Publisher</title>
        <style>
          body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;margin:0;padding:32px;background:#f6f7f8;color:#0d1b0f}
          .card{max-width:760px;margin:0 auto;background:#fff;border:1px solid #e6e8eb;border-radius:16px;padding:28px;box-shadow:0 6px 24px rgba(0,0,0,.06)}
          h1{margin:0 0 8px}
          p{margin:8px 0 0;line-height:1.5}
          a.button{display:inline-block;margin-top:16px;padding:10px 16px;border-radius:10px;border:1px solid #d4dfd6;text-decoration:none}
          code{background:#f1f3f5;padding:2px 6px;border-radius:6px}
        </style>
      </head>
      <body>
        <div class="card">
          <h1>🎉 ${SITE_NAME} Publisher</h1>
          <p>Servidor ativo.</p>
          <p>Endpoints úteis: <code>/health</code>, <code>/smtp-check</code>, <code>/publish</code>, <code>/api/publish</code>.</p>
          <a class="button" href="/health" target="_blank">Ver /health</a>
        </div>
      </body>
    </html>
  `);
});

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok", time: new Date().toISOString() });
});

// mantém compatibilidade com /healthz
app.get("/healthz", (_req, res) => {
  res.status(200).json({ status: "ok", time: new Date().toISOString() });
});

// verificação SMTP manual
app.get("/smtp-check", async (_req, res) => {
  try {
    await transporter.verify();
    res.send("SMTP OK");
  } catch (e) {
    res.status(500).send("SMTP FAIL: " + (e?.message || e));
  }
});

// =====================================================
// Rota de publicação com anexos (aceita docs e docs[])
// =====================================================
const publishHandler = async (req, res) => {
  try {
    const body = req.body || {};

    const payload = {
      nome_empresa: sanitize(body.nome_empresa),
      nome_completo: sanitize(body.nome_completo),
      cpf_cnpj: sanitize(body.cpf_cnpj),
      email: sanitize(body.email),
      telefone: sanitize(body.telefone),
      cidade: sanitize(body.cidade),
      estado: sanitize(body.estado),

      categoria: sanitize(body.categoria),
      subcategoria: sanitize(body.subcategoria),
      produto: sanitize(body.produto),
      preco: sanitize(body.preco),
      aceita_propostas: sanitize(body.aceita_propostas),
      propostas: sanitize(body.propostas),
      entrega: sanitize(body.entrega),
      local: sanitize(body.local),
      descricao: sanitize(body.descricao),
      termos_aceitos:
        String(body.termos_aceitos) === "true" || body.termos_aceitos === "on",
    };

    const missing = [];
    if (!payload.email) missing.push("email");
    if (!payload.nome_completo) missing.push("nome_completo");
    if (!payload.cpf_cnpj) missing.push("cpf_cnpj");
    if (!payload.preco) missing.push("preco");
    if (!payload.entrega) missing.push("entrega");
    if (!payload.termos_aceitos) missing.push("termos_aceitos");

    if (missing.length) {
      return res
        .status(400)
        .json({ ok: false, error: `Campos obrigatórios: ${missing.join(", ")}` });
    }

    // req.files quando usamos fields() vira objeto { docs: [...], 'docs[]': [...] }
    const filesRaw = []
      .concat(req.files?.docs || [])
      .concat(req.files?.["docs[]"] || []);

    const attachments = filesRaw.map((f) => ({
      filename: f.originalname,
      content: f.buffer,
      contentType: f.mimetype,
    }));

    // E-mail p/ fiscalização
    const adminTo = sanitize(REVIEW_EMAIL || ADMIN_EMAIL);
    const adminHtml = buildAdminHtml(payload, filesRaw);

    await transporter.sendMail({
      from: `${SITE_NAME} <${ADMIN_EMAIL}>`,
      to: adminTo,
      subject: `Novo anúncio publicado - ${sanitize(payload.produto || "Produto")}`,
      html: adminHtml,
      attachments,
    });

    // E-mail de boas-vindas ao vendedor
    const welcomeHtml = buildWelcomeHtml(payload);

    await transporter.sendMail({
      from: `${SITE_NAME} <${ADMIN_EMAIL}>`,
      to: payload.email,
      subject: `Bem-vindo(a) ao ${SITE_NAME}! Seu anúncio está no ar`,
      html: welcomeHtml,
    });

    return res.status(200).json({
      ok: true,
      message: "Anúncio publicado e e-mails enviados.",
    });
  } catch (err) {
    console.error("[ERRO /publish]", err?.message || err, err?.stack);
    return res
      .status(500)
      .json({ ok: false, error: "Falha interna ao processar o anúncio." });
  }
};

app.post("/publish", uploadFields, publishHandler);
app.post("/api/publish", uploadFields, publishHandler);

// 404
app.use((_req, res) => {
  res.status(404).json({ ok: false, error: "Rota não encontrada." });
});

// =====================
// Sobe o servidor
// =====================
app.listen(PORT, () => {
  console.log(`[OK] ${SITE_NAME} publisher rodando na porta ${PORT}`);
});
