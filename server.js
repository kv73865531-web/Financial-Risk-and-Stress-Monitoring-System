const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const db = require('./db');

const app = express();
app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','DELETE'],
  allowedHeaders: ['Content-Type']
}));
app.use(express.json());
app.use(express.static('.'));

// ════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════

// Register new user
app.post('/api/register', async (req, res) => {
  console.log('REGISTER HIT:', req.body);
  const { name, email, phone, password, role, security_question, security_answer } = req.body;
  db.query('SELECT id FROM users WHERE email=?', [email], async (err, rows) => {
    console.log('DB query result:', err, rows);
    if (rows && rows.length) return res.json({ success:false, message:'Email already registered.' });
    db.query('SELECT id FROM users WHERE role=? ORDER BY id DESC LIMIT 1',
    [role||'user'], async (err2, roleRows) => {
      let newId;
      if (!roleRows || !roleRows.length) {
        newId = role === 'admin' ? 'ADM-20001' : 'USR-10001';
      } else {
        const lastNum = parseInt(roleRows[0].id.split('-')[1]) + 1;
        const prefix = role === 'admin' ? 'ADM' : 'USR';
        newId = `${prefix}-${lastNum}`;
      }
      const hashed = await bcrypt.hash(password, 10);
      const sql = `INSERT INTO users (id,name,email,phone,password,role,security_question,security_answer)
                   VALUES (?,?,?,?,?,?,?,?)`;
      db.query(sql, [newId,name,email,phone,hashed,role||'user',security_question,security_answer], (err3) => {
        if (err3) return res.json({ success:false, message: err3.sqlMessage });
        db.query('SELECT id,name,email,phone,role,joined_at,security_question FROM users WHERE id=?',
        [newId], (err4, result) => {
          res.json({ success:true, user: result[0] });
        });
      });
    });
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email=? OR phone=? OR id=?', 
  [email, email, email.toUpperCase()], async (err, rows) => {
    if (err || !rows.length) return res.json({ success:false, message:'User not found.' });
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ success:false, message:'Wrong password.' });
    const { password:_, ...safeUser } = user;
    res.json({ success:true, user: safeUser });
  });
});

// Get all users
app.get('/api/users', (req, res) => {
  db.query('SELECT id,name,email,phone,role,joined_at FROM users', (err, rows) => {
    if (err) return res.json({ success:false });
    res.json({ success:true, users: rows });
  });
});

// Delete user
app.delete('/api/users/:id', (req, res) => {
  db.query('DELETE FROM users WHERE id=?', [req.params.id], (err) => {
    if (err) return res.json({ success:false });
    res.json({ success:true });
  });
});

// Update password
app.put('/api/users/:id/password', async (req, res) => {
  const hashed = await bcrypt.hash(req.body.password, 10);
  db.query('UPDATE users SET password=? WHERE id=?', [hashed, req.params.id], (err) => {
    if (err) return res.json({ success:false });
    res.json({ success:true });
  });
});

// Forgot password - lookup
app.post('/api/forgot/lookup', (req, res) => {
  const { lookup } = req.body;
  db.query('SELECT id,name,email,phone,security_question FROM users WHERE email=? OR phone=?',
  [lookup, lookup], (err, rows) => {
    if (err || !rows.length) return res.json({ success:false, message:'Account not found.' });
    res.json({ success:true, user: rows[0] });
  });
});

// Forgot password - verify answer
app.post('/api/forgot/verify', (req, res) => {
  const { id, answer } = req.body;
  db.query('SELECT security_answer FROM users WHERE id=?', [id], (err, rows) => {
    if (err || !rows.length) return res.json({ success:false });
    const match = rows[0].security_answer.toLowerCase() === answer.toLowerCase();
    res.json({ success: match });
  });
});

// Pending admins
app.post('/api/pending', async (req, res) => {
  console.log('PENDING BODY RECEIVED:', JSON.stringify(req.body));  // ADD THIS
  try {
    const { name, email, phone, password, security_question, security_answer } = req.body;
    const hashed = await bcrypt.hash(password, 10);

    db.query(`SELECT id FROM pending_admins ORDER BY requested_at DESC LIMIT 1`, (err0, lastPend) => {
      db.query(`SELECT id FROM users WHERE role='admin' ORDER BY joined_at DESC LIMIT 1`, (err1, lastAdmin) => {
        let maxNum = 20000;
        if (lastPend && lastPend.length) {
          const n = parseInt(lastPend[0].id.split('-')[1]);
          if (!isNaN(n) && n > maxNum) maxNum = n;
        }
        if (lastAdmin && lastAdmin.length) {
          const n = parseInt(lastAdmin[0].id.split('-')[1]);
          if (!isNaN(n) && n > maxNum) maxNum = n;
        }
        const newId = `ADM-${maxNum + 1}`;

        db.query(
          `INSERT INTO pending_admins (id,name,email,phone,password,security_question,security_answer) VALUES (?,?,?,?,?,?,?)`,
          [newId, name, email, phone, hashed, security_question, security_answer],
          (err2) => {
            if (err2) return res.json({ success: false, message: err2.sqlMessage });
            res.json({ success: true });
          }
        );
      });
    });
  } catch(e) {
    res.json({ success: false, message: e.message });
  }
});
app.get('/api/pending', (req, res) => {
  db.query('SELECT * FROM pending_admins', (err, rows) => {
    if (err) return res.json({ success:false });
    res.json({ success:true, pending: rows });
  });
});

app.post('/api/pending/approve/:id', (req, res) => {
  db.query('SELECT * FROM pending_admins WHERE id=?', [req.params.id], (err, rows) => {
    if (err || !rows.length) {
      console.log('Approve error - not found:', err);
      return res.json({ success:false, message:'Pending request not found.' });
    }
    const p = rows[0];
    console.log('Approving:', p);

    // Check admin slots
    db.query("SELECT COUNT(*) as cnt FROM users WHERE role='admin'", (err2, countRows) => {
      if (err2) return res.json({ success:false });
      if (countRows[0].cnt >= 3) return res.json({ success:false, message:'Admin slots full!' });

      db.query(`INSERT INTO users (id,name,email,phone,password,role,security_question,security_answer)
                VALUES (?,?,?,?,?,'admin',?,?)`,
      [p.id,p.name,p.email,p.phone,p.password,p.security_question,p.security_answer],
      (err3) => {
        if (err3) {
          console.log('Insert error:', err3.sqlMessage);
          return res.json({ success:false, message: err3.sqlMessage });
        }
        db.query('DELETE FROM pending_admins WHERE id=?', [p.id], (err4) => {
          if (err4) console.log('Delete error:', err4);
          res.json({ success:true });
        });
      });
    });
  });
});

app.delete('/api/pending/:id', (req, res) => {
  db.query('DELETE FROM pending_admins WHERE id=?', [req.params.id], (err) => {
    if (err) return res.json({ success:false });
    res.json({ success:true });
  });
});

// Recovery code
app.get('/api/recovery', (req, res) => {
  db.query("SELECT setting_value FROM app_settings WHERE setting_key='recovery_code'", (err, rows) => {
    if (err || !rows.length) return res.json({ success:false });
    res.json({ success:true, code: rows[0].setting_value });
  });
});

app.put('/api/recovery', (req, res) => {
  db.query("UPDATE app_settings SET setting_value=? WHERE setting_key='recovery_code'",
  [req.body.code], (err) => {
    if (err) return res.json({ success:false });
    res.json({ success:true });
  });
});

// ════════════════════════════════
//  FINANCE ROUTES
// ════════════════════════════════

app.post('/api/finance/entry', (req, res) => {
  const { user_id, entry_date, income, expense_edited, expenses } = req.body;
  db.query(`INSERT INTO daily_finance (user_id,entry_date,income,expense_edited)
            VALUES (?,?,?,?)
            ON DUPLICATE KEY UPDATE income=VALUES(income), expense_edited=VALUES(expense_edited)`,
  [user_id, entry_date, income, expense_edited ? 1 : 0], (err) => {
    if (err) return res.json({ success:false, message: err.sqlMessage });
    db.query('SELECT id FROM daily_finance WHERE user_id=? AND entry_date=?',
    [user_id, entry_date], (err2, rows) => {
      if (err2 || !rows.length) return res.json({ success:false });
      const finance_id = rows[0].id;
      db.query('DELETE FROM daily_expenses WHERE finance_id=?', [finance_id], (err3) => {
        if (err3) return res.json({ success:false });
        const vals = Object.entries(expenses||{}).filter(([,a])=>a>0).map(([c,a])=>[finance_id,c,a]);
        if (!vals.length) return res.json({ success:true });
        db.query('INSERT INTO daily_expenses (finance_id,category,amount) VALUES ?', [vals], (err4) => {
          if (err4) return res.json({ success:false });
          res.json({ success:true });
        });
      });
    });
  });
});

app.get('/api/finance/:user_id', (req, res) => {
  db.query(`SELECT df.entry_date, df.income, df.expense_edited, df.saved_at,
                   de.category, de.amount
            FROM daily_finance df
            LEFT JOIN daily_expenses de ON df.id = de.finance_id
            WHERE df.user_id=? ORDER BY df.entry_date`,
  [req.params.user_id], (err, rows) => {
    if (err) return res.json({ success:false });
    const result = {};
    rows.forEach(row => {
      const ds = new Date(row.entry_date).toISOString().slice(0,10);
      if (!result[ds]) result[ds] = {
        income: parseFloat(row.income),
        expense_edited: !!row.expense_edited,
        savedAt: row.saved_at,
        expenses: {}
      };
      if (row.category) result[ds].expenses[row.category] = parseFloat(row.amount);
    });
    res.json({ success:true, data: result });
  });
});

app.listen(3000, () => console.log('🚀 Server running at http://localhost:3000'));