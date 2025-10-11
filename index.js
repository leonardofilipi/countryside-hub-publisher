import express from "express";
import axios from "axios";
import bodyParser from "body-parser";

const app = express();
app.use(bodyParser.json());

// Variáveis do ambiente (Render)
const {
  ZOHO_CLIENT_ID,
  ZOHO_CLIENT_SECRET,
  ZOHO_REFRESH_TOKEN,
  ZOHO_API_DOMAIN,
  ZOHO_SENDER_EMAIL,
  PORT = 10000
} = process.env;

// 🔄 Função que gera um novo Access Token automaticamente
async function getAccessToken() {
  const url = `${ZOHO_API_DOMAIN}/oauth/v2/token`;
  const params = new URLSearchParams({
    refresh_token: ZOHO_REFRESH_TOKEN,
    client_id: ZOHO_CLIENT_ID,
    client_secret: ZOHO_CLIENT_SECRET,
    grant_type: "refresh_token",
  });

  const { data } = await axios.post(url, params);
  return data.access_token;
}

// ✉️ Envio de e-mail via API Zoho Mail
app.post("/send-mail", async (req, res) => {
  try {
    const { to, subject, content } = req.body;
    const accessToken = await getAccessToken();

    const mailUrl = `${ZOHO_API_DOMAIN}/zm/mail/v2/users/${ZOHO_SENDER_EMAIL}/messages`;

    const response = await axios.post(
      mailUrl,
      {
        fromAddress: ZOHO_SENDER_EMAIL,
        toAddress: to,
        subject,
        content,
        mailFormat: "html",
      },
      {
        headers: {
          Authorization: `Zoho-oauthtoken ${accessToken}`,
        },
      }
    );

    res.json({ success: true, messageId: response.data.data.messageId });
  } catch (error) {
    console.error("[ERRO AO ENVIAR EMAIL]", error.response?.data || error.message);
    res.status(500).json({ success: false, error: error.response?.data || error.message });
  }
});

// 🚦 Teste de conexão
app.get("/mailapi-check", async (req, res) => {
  try {
    const token = await getAccessToken();
    if (token) return res.send("✅ Zoho Mail API está funcionando corretamente!");
  } catch (err) {
    console.error(err.message);
  }
  res.status(500).send("❌ Falha ao conectar com a Zoho Mail API");
});

app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
