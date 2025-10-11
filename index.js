// index.js (CommonJS) – Countryside Hub Publisher via Zoho Mail API
// Requisitos de env: PORT, SITE_NAME, ALLOWED_ORIGIN (opcional),
// ZOHO_API_DOMAIN, ZOHO_CLIENT_ID, ZOHO_CLIENT_SECRET, ZOHO_REFRESH_TOKEN

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer"); // usar ^1.4.5-lts.1 no package.json
const axios = require("axios");
const qs = require("querystring");

// ---------- Config / Env ----------
const {
  PORT = 3000,
  SITE_NAME = "Countryside Hub",
  ALLOWED_ORIGIN,
  ZOHO_API_DOMAIN,
  ZOHO_CLIENT_ID,
  ZOHO_CLIENT_SECRET,
  ZOHO_REFRESH_TOKEN,
} = process.env;

if (!ZOHO_API_DOMAIN || !ZOHO_CLIENT_ID || !ZOHO_CLIENT_SECRET || !ZOHO_REFRESH_TOKEN) {
  // Não derruba, mas avisa claramente (as rotas de /healthz continuam funcionando)
  console.warn(
    "[WARN] Variáveis da API Zoho ausentes. Defina ZOHO_API_DOMAIN, ZOHO_CLIENT_ID, ZOHO_CLIENT_SECRET e ZOHO_REFRESH_TOKEN."
  );
}

// ---------- App ----------
const app = express();

app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (!ALLOWED_ORIGIN) return cb(null, true);
      const ok =
        origin === ALLOWED_ORIGIN ||
        origin === ALLOWED_ORIGIN.replace(/\/$/, "");
      cb(ok ? null : new Error("Origin not allowed by CORS"), ok);
    },
    credentials: false,
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

app.use(
  "/api/",
  rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Upload (em memória)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 5 },
});

// ---------- Helpers ----------
function sanitize(s = "") {
  return String(s || "").trim();
}
function money(v) {
  const n = Number(String(v).replace(/[^\d.,-]/g, "").replace(",", "."));
  return Number.isFinite(n) ? n.toFixed(2) : "";
}

// Pega access_token a partir do refresh_token (fluxo server-to-server)
async function getAccessToken() {
  if (!ZOHO_CLIENT_ID || !ZOHO_CLIENT_SECRET || !ZOHO_REFRESH_TOKEN) {
    throw new Error("ZOHO OAuth vars missing");
  }
  const url = "https://accounts.zoho.com/oauth/v2/token";
  const body = qs.stringify({
    grant_type: "refresh_token",
    client_id: ZOHO_CLIENT_ID,
    client_secret: ZOHO_CLIENT_SECRET,
    refresh_token: ZOHO_REFRESH_TOKEN,
  });

  const { data } = await axios.post(url, body, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 15000,
  });

  if (!data.access_token) {
    throw new Error("No access_token from Zoho");
  }
  return data.access_token;
}

// Monta payload do Zoho Mail API (/mail/v1/messages)
function buildZohoMessage({ from, to, subject, html, files }) {
  // Attachments precisam ser base64 inline (sem necessidade de conteúdo CID aqui)
  const attachments = (files || []).map((f) => ({
    name: f.filename || f.originalname || "arquivo",
    content: f.buffer.toString("base64"),
    encoding: "base64",
  }));

  return {
    from: { email: from },
    to: [{ email: to }],
    subject,
    content: [
      {
        type: "text/html",
        content: html || "",
      },
    ],
    attachments,
  };
}

async function sendViaZoho(message) {
  if (!ZOHO_API_DOMAIN) throw new Error("ZOHO_API_DOMAIN missing");
  const accessToken = await getAccessToken();
  const url = `${ZOHO_API_DOMAIN}/mail/v1/messages`; // ex.: https://www.zohoapis.com/mail/v1/messages

  const { data } = await axios.post(url, message, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    timeout: 20000,
  });
  return data;
}

// HTML admin
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
    `<p><b>Local para retirada/entrega:</b> ${sanitize(local || "(não informado)")}</p>`,
    `<p><b>Descrição detalhada:</b><br>${(sanitize(descricao) || "(sem descrição)").replace(/\n/g, "<br>")}</p>`,
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
        Este e-mail foi gerado automaticamente pelo formulário de cadastro de anúncio do ${SITE_NAME}.
      </p>
    </div>
  `;
}

// HTML boas-vindas
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
        <li>Responda rápido os interessados;</li>
        <li>Negocie com transparência (preço, entrega/coleta, prazos);</li>
        <li>Evite pagamentos fora dos canais combinados com o comprador.</li>
      </ul>
      <p>Bons negócios! 🚀</p>
      <p>Equipe ${SITE_NAME}</p>
    </div>
  `;
}

// ---------- Rotas básicas ----------
app.get("/", (_req, res) => {
  res.status(200).send("OK");
});

app.get("/healthz", (_req, res) => {
  res.status(200).json({ status: "ok", time: new Date().toISOString() });
});

// Checagem simples da API Zoho (só tenta trocar o refresh_token por access_token)
app.get("/mailapi-check", async (_req, res) => {
  try {
    const t = await getAccessToken();
    res.status(200).send(t ? "MAIL API OK" : "MAIL API FAIL");
  } catch (e) {
    res.status(502).send(`MAIL API FAIL: ${e?.message || e}`);
  }
});

// ---------- Publicação / envio de e-mails ----------
const publishHandler = async (req, res) => {
  try {
    const payload = {
      nome_empresa: sanitize(req.body.nome_empresa),
      nome_completo: sanitize(req.body.nome_completo),
      cpf_cnpj: sanitize(req.body.cpf_cnpj),
      email: sanitize(req.body.email),
      telefone: sanitize(req.body.telefone),
      cidade: sanitize(req.body.cidade),
      estado: sanitize(req.body.estado),
      categoria: sanitize(req.body.categoria),
      subcategoria: sanitize(req.body.subcategoria),
      produto: sanitize(req.body.produto),
      preco: sanitize(req.body.preco),
      aceita_propostas: sanitize(req.body.aceita_propostas),
      propostas: sanitize(req.body.propostas),
      entrega: sanitize(req.body.entrega),
      local: sanitize(req.body.local),
      descricao: sanitize(req.body.descricao),
      termos_aceitos:
        String(req.body.termos_aceitos) === "true" || req.body.termos_aceitos === "on",
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
        .json({ ok: false, error: `Campos obrigatórios ausentes: ${missing.join(", ")}` });
    }

    // Anexos (em memória)
    const files = (req.files || []).map((f) => ({
      filename: f.originalname,
      buffer: f.buffer,
    }));

    const FROM = `adm@countrysidehub.com`; // Remetente do seu domínio Zoho

    // 1) E-mail p/ fiscalização/admin
    const adminHtml = buildAdminHtml(payload, req.files);
    const adminMsg = buildZohoMessage({
      from: FROM,
      to: `adm@countrysidehub.com`, // pode mudar
      subject: `Novo anúncio publicado - ${sanitize(payload.produto || "Produto")}`,
      html: adminHtml,
      files,
    });
    await sendViaZoho(adminMsg);

    // 2) E-mail boas-vindas para o vendedor
    const welcomeHtml = buildWelcomeHtml(payload);
    const welcomeMsg = buildZohoMessage({
      from: FROM,
      to: payload.email,
      subject: `Bem-vindo(a) ao ${SITE_NAME}! Seu anúncio está no ar`,
      html: welcomeHtml,
    });
    await sendViaZoho(welcomeMsg);

    res.status(200).json({ ok: true, message: "Anúncio publicado e e-mails enviados." });
  } catch (err) {
    console.error("[ERRO /api/publish]", err?.response?.data || err?.message || err);
    res
      .status(500)
      .json({ ok: false, error: "Falha interna ao processar o anúncio. Tente novamente." });
  }
};

app.post("/publish", upload.array("docs[]", 5), publishHandler);
app.post("/api/publish", upload.array("docs[]", 5), publishHandler);

// 404 padrão
app.use((_req, res) => {
  res.status(404).json({ ok: false, error: "Rota não encontrada." });
});

// Sobe servidor
app.listen(PORT, () => {
  console.log(`[OK] ${SITE_NAME} publisher rodando na porta ${PORT}`);
});
