import express from "express";
import nodemailer from "nodemailer";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();
const app = express();
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Página inicial
app.get("/", (req, res) => {
  res.send("🌾 Countryside Hub Publisher ativo e rodando!");
});

// Endpoint de cadastro de anúncio
app.post("/api/register", async (req, res) => {
  const { nome, email, produto, preco, aceitaPropostas, entrega, cidade } = req.body;

  try {
    // Configuração do envio de e-mails
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.ADMIN_EMAIL,
        pass: process.env.ADMIN_EMAIL_PASSWORD,
      },
    });

    // E-mail para o administrador
    await transporter.sendMail({
      from: process.env.ADMIN_EMAIL,
      to: process.env.ADMIN_EMAIL,
      subject: `Novo anúncio cadastrado por ${nome}`,
      html: `
        <h2>🧾 Novo anúncio no Countryside Hub</h2>
        <p><b>Nome:</b> ${nome}</p>
        <p><b>Email:</b> ${email}</p>
        <p><b>Produto:</b> ${produto}</p>
        <p><b>Preço:</b> R$ ${preco}</p>
        <p><b>Aceita propostas:</b> ${aceitaPropostas}</p>
        <p><b>Entrega:</b> ${entrega}</p>
        <p><b>Cidade:</b> ${cidade}</p>
      `,
    });

    // E-mail de confirmação para o vendedor
    await transporter.sendMail({
      from: process.env.ADMIN_EMAIL,
      to: email,
      subject: "Seu anúncio foi publicado no Countryside Hub 🌾",
      html: `
        <h2>Olá ${nome}!</h2>
        <p>Seu anúncio foi publicado com sucesso.</p>
        <p><b>Produto:</b> ${produto}</p>
        <p><b>Preço:</b> R$ ${preco}</p>
        <p>Agora ele está visível para os compradores do Countryside Hub!</p>
        <br />
        <p>Equipe Countryside Hub 🐎</p>
      `,
    });

    res.status(200).json({ message: "Cadastro e e-mails enviados com sucesso!" });
  } catch (error) {
    console.error("Erro ao enviar:", error);
    res.status(500).json({ error: "Erro ao processar cadastro" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
