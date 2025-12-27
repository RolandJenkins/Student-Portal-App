 
  const sqlite3 = require('sqlite3').verbose();
  const fs = require('fs');
  const path = require('path');
  
  const dbPath = path.join(__dirname, 'database', 'student_portal.db');
  
  // Ensure the folder exists
  if (!fs.existsSync(path.join(__dirname, 'database'))) {
    fs.mkdirSync(path.join(__dirname, 'database'));
  }
  
  // Create new database
  const db = new sqlite3.Database(dbPath);
  
  db.serialize(() => {
    db.run(`CREATE TABLE login (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    )`);
  
    const stmt = db.prepare(`INSERT INTO login (username, password, role) VALUES (?, ?, ?)`);
    stmt.run('student1', 'password123', 'student');
    stmt.run('profsmith', 'secure456', 'faculty');
    stmt.finalize();
  
    console.log('✅ New database created with demo accounts.');
  

  console.log('✅ New database created with demo accounts.');
});

db.close();
