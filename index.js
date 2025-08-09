// Importeren van de express module in node_modules
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
require('dotenv').config();
const Database = require('./classes/database.js');
const path = require('path');
const multer = require("multer");
const upload = multer({ dest: "images/" }); // Opslaglocatie voor geüploade afbeeldingen

// Aanmaken van een express app
const app = express();

// Enable CORS
app.use(
  cors({
    origin: 'http://localhost:8080', // Allow requests from this origin
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allowed HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'], // Allowed headers
    credentials: true, // Zorg ervoor dat sessiecookies worden doorgestuurd
  })
);

// Middleware om JSON-requests te parsen
app.use(bodyParser.json());

//endpoints



// Starten van de server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});