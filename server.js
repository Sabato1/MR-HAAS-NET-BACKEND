const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Kuunganisha faili la Database tulilotengeneza
const db = require('./database.js');

app.use(express.json());

// Njia ya kuangalia kama server inafanya kazi
app.get('/', (req, res) => {
    res.json({ message: "Karibu kwenye HAAS WISP CLOUD Backend!" });
});

// Kuanzisha Server
app.listen(PORT, () => {
    console.log(`Server inaendelea vizuri kwenye port ${PORT}`);
});
