const mysql = require('mysql2/promise');
const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'tarun123',
  database: 'noc'
});

module.exports = db;
