mathias-network-starter/
├─ backend/
│  ├─ package.json
│  ├─ server.js
│  ├─ routes/auth.js
│  ├─ routes/products.js
│  ├─ routes/checkout.js
│  ├─ lib/wg.js
│  ├─ .env.example
│  └─ scripts/generate_keys.sh
├─ frontend/
│  ├─ package.json
│  ├─ pages/index.js
│  ├─ pages/login.js
│  ├─ pages/products.js
│  ├─ pages/checkout.js
│  └─ next.config.js
├─ node-agent/
│  ├─ agent.py
│  └─ requirements.txt
├─ installers/
│  └─ node_installer.sh
└─ README.md{
  "name": "mathias-network-backend",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "body-parser": "^1.20.2",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "nodemailer": "^6.9.4",
    "uuid": "^9.0.0"
  }
}PORT=4000
JWT_SECRET=change_this_secret
ADMIN_EMAIL=you@example.com
NODE_SERVER_PUBLIC_IP=your.node.public.ip
WG_SERVER_PUBLIC_KEY=replace_with_server_pubkey
WG_ENDPOINT=your.node.public.ip:51820const express = require('express');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');
const productsRoutes = require('./routes/products');
const checkoutRoutes = require('./routes/checkout');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

app.use('/api/auth', authRoutes);
app.use('/api/products', productsRoutes);
app.use('/api/checkout', checkoutRoutes);

app.get('/', (req, res) => res.send('Mathias Network Backend'));

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Backend listening on ${port}`));const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

// In-memory users store for starter (replace with DB)
const users = [];

router.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (users.find(u => u.email === email)) return res.status(400).json({message:'email exists'});
  const hash = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), name, email, password: hash };
  users.push(user);
  const token = jwt.sign({id:user.id,email:user.email}, process.env.JWT_SECRET || 'secret');
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ message: 'not found' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ message: 'invalid' });
  const token = jwt.sign({id:user.id,email:user.email}, process.env.JWT_SECRET || 'secret');
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

module.exports = router;const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');

// In-memory products (replace with DB)
let products = [
  { id: 'p1', name: '1 hour - Bungoma Node', type: 'time', value: 60, price: 100 },
  { id: 'p2', name: '1 GB - Bungoma Node', type: 'gb', value: 1, price: 150 }
];

router.get('/', (req, res) => res.json(products));

router.post('/', (req, res) => {
  // Admin create product (very basic)
  const { name, type, value, price } = req.body;
  const p = { id: uuidv4(), name, type, value, price };
  products.push(p);
  res.json(p);
});

module.exports = router;// helper to generate WireGuard keys using system wg command
const fs = require('fs');
const { execSync } = require('child_process');

function genKeypair(prefix) {
  const priv = execSync('wg genkey').toString().trim();
  const pub = execSync(`echo "${priv}" | wg pubkey`).toString().trim();
  const basePath = './wg_keys';
  if (!fs.existsSync(basePath)) fs.mkdirSync(basePath);
  fs.writeFileSync(`${basePath}/${prefix}_private.key`, priv);
  fs.writeFileSync(`${basePath}/${prefix}_public.key`, pub);
  return { priv, pub };
}

function makeClientConf({ clientPriv, clientAddr, dns }){
  const serverPub = process.env.WG_SERVER_PUBLIC_KEY || '';
  const endpoint = process.env.WG_ENDPOINT || '';
  return ` [Interface]\nPrivateKey = ${clientPriv}\nAddress = ${clientAddr}\nDNS = ${dns || '1.1.1.1'}\n\n[Peer]\nPublicKey = ${serverPub}\nEndpoint = ${endpoint}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;
}

module.exports = { genKeypair, makeClientConf };const express = require('express');
const router = express.Router();
const { genKeypair, makeClientConf } = require('../lib/wg');
const { v4: uuidv4 } = require('uuid');

// In-memory purchases + peers
const purchases = [];

// Simple endpoint to simulate checkout (mock STK)
router.post('/initiate', async (req, res) => {
  const { userId, productId } = req.body;
  // In real flow: call Daraja STK push and wait for confirmation webhook
  // For starter: assume payment succeeds immediately
  const purchase = { id: uuidv4(), userId, productId, status: 'paid', createdAt: Date.now() };
  purchases.push(purchase);

  // generate client wg keys and conf
  const pair = genKeypair(`peer_${purchase.id}`);
  const clientAddr = `10.66.66.${Math.floor(Math.random()*200)+2}/32`;
  const conf = makeClientConf({ clientPriv: pair.priv, clientAddr });

  // *** IMPORTANT: backend should instruct node to add peer. For starter, we only return conf. ***
  res.json({ purchase, client_conf: conf });
});

module.exports = router;#!/bin/bash
set -e
if ! command -v wg >/dev/null; then
  echo "wg not installed. On Debian/Ubuntu: apt install wireguard"
  exit 1
fi
PRFX=$1
wg genkey | tee ${PRFX}_private.key | wg pubkey > ${PRFX}_public.key
echo "Generated ${PRFX}_private.key and ${PRFX}_public.key"{
  "name": "mathias-network-frontend",
  "version": "1.0.0",
  "scripts": {
    "dev": "next dev -p 3000",
    "build": "next build",
    "start": "next start -p 3000"
  },
  "dependencies": {
    "next": "13.4.7",
    "react": "18.2.0",
    "react-dom": "18.2.0",
    "axios": "1.4.0"
  }
}module.exports = { reactStrictMode: true }import Link from 'next/link';
export default function Home(){
  return (
    <div style={{padding:20,fontFamily:'sans-serif'}}>
      <h1>Mathias Network</h1>
      <p>Welcome — a starter frontend for your wide internet sharing network.</p>
      <nav>
        <Link href="/products">Products</Link> | <Link href="/login">Login / Signup</Link>
      </nav>
    </div>
  )
}import { useState } from 'react';
import axios from 'axios';
import { useRouter } from 'next/router';

export default function Login(){
  const [email,setEmail]=useState('');
  const [password,setPassword]=useState('');
  const router = useRouter();

  async function signup(){
    const r = await axios.post('http://localhost:4000/api/auth/signup',{ name: 'User', email, password });
    localStorage.setItem('token', r.data.token);
    router.push('/products');
  }
  async function login(){
    const r = await axios.post('http://localhost:4000/api/auth/login',{ email, password });
    localStorage.setItem('token', r.data.token);
    router.push('/products');
  }

  return (
    <div style={{padding:20}}>
      <h2>Login / Signup</h2>
      <input placeholder="email" value={email} onChange={e=>setEmail(e.target.value)} /> <br/>
      <input placeholder="password" value={password} onChange={e=>setPassword(e.target.value)} type="password" /> <br/>
      <button onClick={signup}>Signup</button>
      <button onClick={login}>Login</button>
    </div>
  )
}import axios from 'axios';
import Link from 'next/link';
import { useEffect, useState } from 'react';

export default function Products(){
  const [products,setProducts] = useState([]);
  useEffect(()=>{ axios.get('http://localhost:4000/api/products').then(r=>setProducts(r.data)) },[])
  return (
    <div style={{padding:20}}>
      <h2>Products</h2>
      <ul>
        {products.map(p=> (
          <li key={p.id}>{p.name} — KES {p.price} <Link href={`/checkout?product=${p.id}`}><a>Buy</a></Link></li>
        ))}
      </ul>
    </div>
  )
}import { useRouter } from 'next/router';
import axios from 'axios';
import { useState, useEffect } from 'react';

export default function Checkout(){
  const r = useRouter();
  const { product } = r.query;
  const [user,setUser] = useState(null);
  useEffect(()=>{ setUser({ id: 'u-test' }) },[]);

  async function buy(){
    const res = await axios.post('http://localhost:4000/api/checkout/initiate',{ userId: user.id, productId: product });
    // response contains `client_conf` — prompt user to download
    const conf = res.data.client_conf;
    const blob = new Blob([conf], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'wg_peer.conf';
    a.click();
  }

  return (
    <div style={{padding:20}}>
      <h2>Checkout</h2>
      <p>Buying product: {product}</p>
      <button onClick={buy}>Pay (mock) & Download WireGuard config</button>
    </div>
  )
}# Simple Node Agent: listens for add_peer requests from central backend
# Usage: python3 agent.py --token YOUR_NODE_TOKEN --wg-iface wg0

from flask import Flask, request, jsonify
import subprocess
import argparse
import os

app = Flask(__name__)

@app.route('/add_peer', methods=['POST'])
def add_peer():
    data = request.json
    pubkey = data.get('pubkey')
    allowed_ip = data.get('allowed_ip')
    iface = os.environ.get('WG_IFACE','wg0')
    # run wg set command
    try:
        subprocess.check_output(['wg','set',iface,'peer',pubkey,'allowed-ips',allowed_ip])
        return jsonify({'ok':True})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}),500

if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host','-H', default='0.0.0.0')
    parser.add_argument('--port','-p', type=int, default=8000)
    args = parser.parse_args()
    app.run(host=args.host, port=args.port)Flask==2.2.5#!/bin/bash
set -e
# Run as root on Debian/Ubuntu Raspberry Pi
apt update && apt install -y wireguard python3-pip
pip3 install flask
# create a directory
mkdir -p /opt/mathias-agent
cat > /opt/mathias-agent/agent.py <<'PY'
# (paste the agent.py content here if you copy manually)
PY
cat > /etc/systemd/system/mathias-agent.service <<'SVC'
[Unit]
Description=Mathias Node Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/mathias-agent/agent.py --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload
systemctl enable --now mathias-agent

echo "Installed mathias agent and started service."# Mathias Network Starter

This repo is a starter kit for a distributed internet-sharing network. It provides a minimal backend API, a simple Next.js frontend, and node tools for WireGuard automation.

## Quickstart

1. Backend

```bash
cd backend
cp .env.example .env
npm install
npm startcd frontend
npm install
npm run dev# on node
sudo bash installers/node_installer.sh
# or manually run agent
python3 node-agent/agent.pyPORT=4000
MPESA_CONSUMER_KEY=your_consumer_key_here
MPESA_CONSUMER_SECRET=your_consumer_secret_here
MPESA_SHORTCODE=174379                # sample sandbox shortcode
MPESA_PASSKEY=your_passkey_here
MPESA_CALLBACK_BASE=https://yourdomain.com    # base URL for callbacks (no trailing slash)
MPESA_ENV=sandbox                     # "sandbox" or "production"
JWT_SECRET=replace_this_secretnpm install express axios body-parser dotenv// mpesa.js
// Usage: const mpesa = require('./mpesa');
// await mpesa.getAccessToken(); await mpesa.stkPush({...});

const axios = require('axios');
const qs = require('querystring');

require('dotenv').config();

const ENV = process.env.MPESA_ENV || 'sandbox';

const ENDPOINTS = {
  sandbox: {
    oauth: 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
    stkPush: 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
  },
  production: {
    oauth: 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
    stkPush: 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
  }
}[ENV];

let cachedToken = null;
let tokenExpiry = 0;

async function getAccessToken(){
  const now = Date.now();
  if (cachedToken && now < tokenExpiry - 30*1000) return cachedToken; // reuse if not near expiry

  const key = process.env.MPESA_CONSUMER_KEY;
  const secret = process.env.MPESA_CONSUMER_SECRET;
  if (!key || !secret) throw new Error('MPESA_CONSUMER_KEY and MPESA_CONSUMER_SECRET must be set in .env');

  const auth = Buffer.from(`${key}:${secret}`).toString('base64');

  const res = await axios.get(ENDPOINTS.oauth, {
    headers: { Authorization: `Basic ${auth}` }
  });

  const data = res.data;
  // data.access_token, data.expires_in
  cachedToken = data.access_token;
  tokenExpiry = Date.now() + (parseInt(data.expires_in || 3600,10) * 1000);
  return cachedToken;
}

function getTimestamp(){
  const d = new Date();
  const YYYY = d.getFullYear().toString();
  const MM = String(d.getMonth()+1).padStart(2,'0');
  const DD = String(d.getDate()).padStart(2,'0');
  const hh = String(d.getHours()).padStart(2,'0');
  const mm = String(d.getMinutes()).padStart(2,'0');
  const ss = String(d.getSeconds()).padStart(2,'0');
  return `${YYYY}${MM}${DD}${hh}${mm}${ss}`;
}

function generatePassword(shortcode, passkey, timestamp){
  const str = `${shortcode}${passkey}${timestamp}`;
  return Buffer.from(str).toString('base64');
}

/**
 * stkPush payload
 * @param {Object} opts
 * opts: {
 *   amount, phone, accountReference, transactionDesc, callbackURL
 * }
 */
async function stkPush(opts){
  const shortcode = process.env.MPESA_SHORTCODE;
  const passkey = process.env.MPESA_PASSKEY;
  if (!shortcode || !passkey) throw new Error('MPESA_SHORTCODE and MPESA_PASSKEY must be set in .env');

  const token = await getAccessToken();
  const timestamp = getTimestamp();
  const password = generatePassword(shortcode, passkey, timestamp);

  const payload = {
    BusinessShortCode: shortcode,
    Password: password,
    Timestamp: timestamp,
    TransactionType: 'CustomerPayBillOnline',
    Amount: opts.amount,
    PartyA: opts.phone,            // customer's msisdn in format 2547XXXXXXXX
    PartyB: shortcode,
    PhoneNumber: opts.phone,
    CallBackURL: opts.callbackURL,
    AccountReference: opts.accountReference || 'account',
    TransactionDesc: opts.transactionDesc || 'Payment'
  };

  const res = await axios.post(ENDPOINTS.stkPush, payload, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });

  return res.data; // contains CheckoutRequestID and ResponseCode/Description usually
}

module.exports = { getAccessToken, stkPush };// server.js
const express = require('express');
const bodyParser = require('body-parser');
const mpesa = require('./mpesa');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// In-memory purchases store for demo
const purchases = {}; // purchaseId -> { id, amount, phone, status, checkoutRequestID, receipt }

// 1) Initiate a mock purchase & call STK push
// POST /api/pay
// body: { purchaseId, amount, phone }
app.post('/api/pay', async (req, res) => {
  try {
    const { purchaseId, amount, phone } = req.body;
    if (!purchaseId || !amount || !phone) return res.status(400).json({ error: 'purchaseId, amount, phone required' });

    // build callback URL: MPESA_CALLBACK_BASE must be set
    const base = process.env.MPESA_CALLBACK_BASE;
    if (!base) return res.status(500).json({ error: 'MPESA_CALLBACK_BASE not set' });

    const callbackURL = `${base}/api/mpesa/callback`;
    const result = await mpesa.stkPush({
      amount,
      phone,
      accountReference: purchaseId,
      transactionDesc: `Payment for ${purchaseId}`,
      callbackURL
    });

    // Save purchase pending
    purchases[purchaseId] = { id: purchaseId, amount, phone, status: 'pending', stkRequest: result };
    return res.json({ ok: true, result });
  } catch (err) {
    console.error('pay error', err?.response?.data || err.message || err);
    return res.status(500).json({ error: err.message });
  }
});

// 2) Callback endpoint that Safaricom will POST to
// POST /api/mpesa/callback
app.post('/api/mpesa/callback', async (req, res) => {
  // Safaricom expects a 200 quickly with the response it receives (ack)
  try {
    const body = req.body;
    // The structure: body.Body.stkCallback
    const stk = (body && body.Body && body.Body.stkCallback) ? body.Body.stkCallback : null;
    if (!stk) {
      console.warn('No stkCallback in body', JSON.stringify(body).slice(0,200));
      return res.json({ resultCode: 0, resultDesc: 'Received' });
    }

    const checkoutRequestID = stk.CheckoutRequestID;
    const resultCode = stk.ResultCode; // 0 means success
    const resultDesc = stk.ResultDesc;

    // Find matching purchase by matching AccountReference inside CallbackMetadata? Some implementations map via CheckoutRequestID
    // Check metadata if success
    if (resultCode === 0) {
      // success: get MpesaReceiptNumber and Amount
      let mpesaReceipt = null;
      let amount = null;
      let phone = null;
      if (stk.CallbackMetadata && stk.CallbackMetadata.Item) {
        for (const item of stk.CallbackMetadata.Item) {
          if (item.Name === 'MpesaReceiptNumber') mpesaReceipt = item.Value;
          if (item.Name === 'Amount') amount = item.Value;
          if (item.Name === 'PhoneNumber') phone = item.Value;
        }
      }
      // Try to find purchase matching AccountReference from original request or use CheckoutRequestID mapping
      // For demo we look for a purchase with pending status and same phone & amount
      const found = Object.values(purchases).find(p => p.phone==phone && p.amount==amount && p.status==='pending');
      if (found) {
        found.status = 'paid';
        found.checkoutRequestID = checkoutRequestID;
        found.receipt = mpesaReceipt;
        console.log('Purchase marked paid', found.id, mpesaReceipt);
      } else {
        console.log('Successful payment but purchase not found (store details for reconciliation)', { checkoutRequestID, mpesaReceipt, amount, phone });
      }
    } else {
      console.log('Payment failed or canceled', { checkoutRequestID, resultCode, resultDesc });
      // mark pending purchase as failed if you can find it
    }

    // IMPORTANT: respond quickly with 200 and the expected JSON acknowledgement
    return res.json({
      "ResultCode": 0,
      "ResultDesc": "Received"
    });
  } catch (err) {
    console.error('callback handler error', err);
    return res.status(500).json({ ResultCode: 1, ResultDesc: 'InternalError' });
  }
});

const port = process.env.PORT || 4000;
app.listen(port, ()=> console.log(`Server running on ${port}`));# WiFi-connection-
Wifi connection 
