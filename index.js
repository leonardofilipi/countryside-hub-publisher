// index.js
// Countryside Hub Publisher – Node.js + Express + Nodemailer (Zoho Mail Individual)

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const multer = require("multer");

// =========================
// Environment Config
// =========================
const {
  PORT = 3000,
  SITE_NAME = "Countryside Hub",
  ADMIN_EMAIL,
  ADMIN_EMAIL_PASSWORD,
  REVIEW_EMAIL,
  ALLOWED_ORIGIN,
  ZOHO_SMTP_HOST = "smtp.zoho.com", // SMTP padrão para contas individuais
  ZOHO_SMTP_PORT = "587",
  ZOHO_SMTP_SECURE = "false",
} = process.env;

if (!ADMIN_EMAIL || !ADMIN_EMAIL_PASSWORD) {
  console.error(
    "[ERRO] ADMIN_EMAIL e ADMIN_EMAIL_PASSWORD (App Password do Zoho) são obrigatórios."
  );
  process.exit(1);
}

// =========================
// App Setup
// =========================
const app = express();
app.use(helmet({ crossOriginResourcePolicy: false }));
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
  })
);
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

// =========================
// Rate Limit
// =========================
app.use(
  "/api/",
  rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// =========================
// File Uploads
// =========================
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 5 },
});

// =========================
// SMTP Transporter (Zoho)
// =========================
async function createTransporter() {
  const tryOptions = [
    {
      host: ZOHO_SMTP_HOST,
      port: 587,
      secure: false,
    },
    {
      host: ZOHO_SMTP_HOST,
      port: 465,
      secure: true,
    },
  ];

  for (const opts of tryOptions) {
    try {
      const transporter = nodemailer.createTransport({
        ...opts,
        auth: {
          user: ADMIN_EMAIL,
          pass: ADMIN_EMAIL_PASSWORD,
        },
        tls: {
          minVersion: "TLSv1.2",
          rejectUnauthorized: false,
        },
      });

      await transporter.verify();
      console.log(
        `[OK] SMTP verificado com sucesso em ${opts.host}:${opts.port} (secure=${opts.secure})`
      );
      return transporter;
    } catch (e) {
      console.warn(
        `[Aviso] Falha ao conectar em ${opts.host}:${opts.port}: ${e.message}`
      );
    }
  }

  throw new Error("Não foi possível conectar ao servidor SMTP da Zoho.");
}

let transporterPromise = createTransporter();

// =========================
// Utils
// =========================
function sanitize(str = "") {
  return String(str).trim();
}
function money(v) {
  const n = Number(String(v).replace(/[^\d.,-]/g, "").replace(",", "."));
  return Number.isFinite(n) ? n.toFixed(2) : "";
}
function buildAdminHtml(payload, filesInfo) {
  const linhas = Object.entries(payload)
    .map(([k, v]) => `<p><b>${k}:</b> ${sanitize(v)}</p>`)
    .join("\n");
  const anexos =
    filesInfo?.length > 0
      ? `<p><b>Anexos:</b> ${filesInfo
          .map((f) => f.originalname)
          .join(", ")}</p>`
      : "";
  return `
  <div style="font-family:Arial,sans-serif">
    <h2>📢 Novo anúncio publicado</h2>
    ${linhas}
    ${anexos}
    <hr><p>Gerado automaticamente pelo ${SITE_NAME}</p>
  </div>`;
}
function buildWelcomeHtml(payload) {
  return `
  <div style="font-family:Arial,sans-serif">
    <h2>Bem-vindo(a) ao ${SITE_NAME}!</h2>
    <p>Olá ${sanitize(payload.nome_completo)} 👋</p>
    <p>Seu anúncio <b>${sanitize(payload.produto)}</b> foi publicado com sucesso!</p>
    <p>Equipe ${SITE_NAME}</p>
  </div>`;
}

// =========================
// Routes
// =========================
app.get("/", (req, res) => {
  res.status(200).send("OK - Countryside Hub Publisher ativo");
});

app.get("/healthz", (req, res) => {
  res.status(200).json({ status: "ok", time: new Date().toISOString() });
});

app.get("/smtp-check", async (req, res) => {
  try {
    const t = await transporterPromise;
    await t.verify();
    res.status(200).send("SMTP OK");
  } catch (e) {
    res.status(500).send("SMTP FAIL: " + e.message);
  }
});

const handler = async (req, res) => {
  try {
    const payload = req.body;
    const files = (req.files || []).map((f) => ({
      filename: f.originalname,
      content: f.buffer,
      contentType: f.mimetype,
    }));
    const transporter = await transporterPromise;

    // Envia para o admin
    await transporter.sendMail({
      from: `${SITE_NAME} <${ADMIN_EMAIL}>`,
      to: REVIEW_EMAIL || ADMIN_EMAIL,
      subject: `Novo anúncio: ${sanitize(payload.produto)}`,
      html: buildAdminHtml(payload, req.files),
      attachments: files,
    });

    // E-mail de boas-vindas
    await transporter.sendMail({
      from: `${SITE_NAME} <${ADMIN_EMAIL}>`,
      to: payload.email,
      subject: `Bem-vindo(a) ao ${SITE_NAME}!`,
      html: buildWelcomeHtml(payload),
    });

    res.status(200).json({ ok: true, message: "E-mails enviados com sucesso." });
  } catch (e) {
    console.error("[ERRO /publish]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
};

app.post("/publish", upload.array("docs[]", 5), handler);
app.post("/api/publish", upload.array("docs[]", 5), handler);

app.use((_req, res) =>
  res.status(404).json({ ok: false, error: "Rota não encontrada." })
);

// =========================
// Start Server
// =========================
app.listen(PORT, () =>
  console.log(`[OK] ${SITE_NAME} publisher rodando na porta ${PORT}`)
);
