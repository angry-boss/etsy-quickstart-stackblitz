// server.js
//require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const API = 'https://api.etsy.com/v3';

app.get('/', (_,res)=>res.send(
  `<h3>Etsy Quick Start (StackBlitz)</h3>
   <p><a href="/ping" target="_blank">Ping API (без OAuth)</a></p>
   <p><a href="/login">OAuth Login (PKCE)</a></p>`
));

// 1) Пинг из Quick Start — без OAuth, только x-api-key
app.get('/ping', async (req, res) => {
  const r = await fetch(`${API}/application/openapi-ping`, {
    headers: { 'x-api-key': process.env.CLIENT_ID }
  });
  res.type('text/plain').send(await r.text());
});

// ===== PKCE helpers (из требований Etsy: Authorization Code + PKCE) =====
const store = new Map(); // state -> verifier
const b64url = b => b.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const mkVerifier = () => b64url(crypto.randomBytes(64));
const mkChallenge = v => b64url(crypto.createHash('sha256').update(v).digest());

// 2) Старт OAuth
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(8).toString('hex');
  const verifier = mkVerifier();
  store.set(state, verifier);

  const params = new URLSearchParams({
    response_type: 'code',
    redirect_uri: process.env.REDIRECT_URI,
    scope: (process.env.SCOPES||'').trim(),
    client_id: process.env.CLIENT_ID,
    state,
    code_challenge: mkChallenge(verifier),
    code_challenge_method: 'S256'
  });

  res.redirect(`https://www.etsy.com/oauth/connect?${params.toString()}`);
});

// 3) Callback: обмен кода на токен и пробный защищённый вызов
app.get('/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const verifier = store.get(state);
    if (!verifier) throw new Error('Missing PKCE state');

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: process.env.CLIENT_ID,
      redirect_uri: process.env.REDIRECT_URI,
      code,
      code_verifier: verifier
    });

    const t = await fetch(`${API}/public/oauth/token`, {
      method: 'POST',
      headers: { 'content-type':'application/x-www-form-urlencoded' },
      body
    });
    const tokens = await t.json();
    if (!t.ok) return res.status(400).json(tokens);

    // пример защищённого вызова (замени shop_id на свой)
    const url = `${API}/application/listings?shop_id=${process.env.SHOP_ID}&state=active`;
    const r = await fetch(url, {
      headers: {
        'x-api-key': process.env.CLIENT_ID,
        'authorization': `Bearer ${tokens.access_token}`
      }
    });
    const txt = await r.text();
    res.type('text/plain').send(`OK. Access token получен.\n\nGET ${url}\n\n${txt}`);
  } catch (e) {
    res.status(400).send(String(e));
  }
});

app.listen(PORT, ()=>console.log(`http://localhost:${PORT}`));