// MR HAAS NET - Backend - Siza Ukerewe mrhaas.net
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Portal Data - Siza Ukerewe
const PORTAL_INFO = {
  name: "MR HAAS NET",
  location: "Siza - Ukerewe",
  portal: "mrhaas.net",
  gateway: "10.10.0.65",
  duckdns: "mrhaasnet.duckdns.org",
  admin: "HAAS48-9PM-7E5"
};

// Routes
app.get('/', (req, res) => {
  res.json({ status: "MR HAAS NET Backend Online", ...PORTAL_INFO });
});

app.get('/api/status', (req, res) => {
  res.json({ online: true, clients: 0, ...PORTAL_INFO });
});

app.post('/api/login', (req, res) => {
  const { voucher, phone } = req.body;
  if(voucher === "HAAS48-9PM-7E5" || voucher){
    res.json({ success: true, message: "Karibu MR HAAS NET - Siza", ip: "10.10.0.65" });
  } else {
    res.json({ success: false, message: "Voucher si sahihi" });
  }
});

app.get('/api/devices', (req, res) => {
  res.json([]);
});

app.listen(PORT, () => {
  console.log(`MR HAAS NET Backend running on ${PORT}`);
});
