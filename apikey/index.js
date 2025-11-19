const express = require('express')
const path = require('path')
const crypto = require('crypto')
const bcrypt = require('bcryptjs') // <-- added
const mysql = require('mysql2/promise') // pakai versi promise
const app = express()
const port = 3000

app.use(express.static(path.join(__dirname, 'public')))
app.use(express.json())

const dbConfig = {
  host: 'localhost',    
  user: 'root',         
  password: '12345678',         
  database: 'APIKey'
}

let connection

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

// generate API key (tidak disimpan)
app.post('/generate', async (req, res) => {
  try {
    const apiKey = crypto.randomBytes(32).toString('hex') // 64 hex chars
    res.json({ success: true, apiKey })
  } catch (err) {
    console.error(err)
    res.status(500).json({ success: false, message: 'Gagal generate API key' })
  }
})

// menyimpan API lalu User (saat user submit)
app.post('/user', async (req, res) => {
  const { FirstName, LastName, Email, apiKey } = req.body
  if (!FirstName || !LastName || !Email || !apiKey) return res.status(400).json({ success:false, message: 'Field wajib diisi' })
  try {
    // insert API
    const [r] = await connection.execute('INSERT INTO API (ApiKey) VALUES (?)', [apiKey])
    const keyId = r.insertId
    // insert User
    await connection.execute('INSERT INTO User (FirstName, LastName, Email, key_id) VALUES (?,?,?,?)', [FirstName, LastName, Email, keyId])
    res.json({ success: true })
  } catch (err) {
    console.error(err)
    res.status(500).json({ success:false, message:'Gagal menyimpan ke database' })
  }
})

// Admin: simple in-memory session tokens
const sessions = new Map()

// helper untuk hash password (bcrypt -> ~60 chars)
function hashPassword(password) {
  const saltRounds = 10
  return bcrypt.hashSync(password, saltRounds) // returns ~60 char string
}

function verifyPassword(password, stored) {
  try {
    return bcrypt.compareSync(password, stored)
  } catch (e) {
    return false
  }
}

// admin register
app.post('/admin/register', async (req, res) => {
  const { Email, Password } = req.body
  if (!Email || !Password) return res.status(400).json({ success:false, message:'Email & Password required' })
  try {
    const pwdHash = hashPassword(Password)
    await connection.execute('INSERT INTO Admin (Email, Password) VALUES (?, ?)', [Email, pwdHash])
    res.json({ success:true })
  } catch (err) {
    console.error(err)
    res.status(500).json({ success:false, message:'Gagal register' })
  }
})

// admin login -> return token
app.post('/admin/login', async (req, res) => {
  const { Email, Password } = req.body
  if (!Email || !Password) return res.status(400).json({ success:false, message:'Email & Password required' })
  try {
    const [rows] = await connection.execute('SELECT * FROM Admin WHERE Email = ?', [Email])
    if (rows.length === 0) return res.status(401).json({ success:false, message:'Email tidak ditemukan' })
    const admin = rows[0]
    if (!verifyPassword(Password, admin.Password)) return res.status(401).json({ success:false, message:'Password salah' })
    const token = crypto.randomBytes(24).toString('hex')
    sessions.set(token, { admin_id: admin.admin_id, Email: admin.Email, created: Date.now() })
    res.json({ success:true, token })
  } catch (err) {
    console.error(err)
    res.status(500).json({ success:false, message:'Gagal login' })
  }
})

// middleware auth for admin endpoints
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || ''
  const token = h.startsWith('Bearer ') ? h.slice(7) : null
  if (!token || !sessions.has(token)) return res.status(401).json({ success:false, message:'Unauthorized' })
  req.admin = sessions.get(token)
  next()
}

// serve dashboard page
app.get('/admin/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin_dashboard.html'))
})

// serve admin page (tambah ini)
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'))
})

// get users + api for admin
app.get('/admin/users', authMiddleware, async (req, res) => {
  try {
    const [rows] = await connection.execute(
      `SELECT u.user_id, u.FirstName, u.LastName, u.Email, a.ApiKey, a.OutOfDate, a.key_id
       FROM User u JOIN API a ON u.key_id = a.key_id
       ORDER BY u.user_id DESC`
    )
    const now = new Date()
    const data = rows.map(r=>{
      const out = new Date(r.OutOfDate)
      const diffDays = Math.floor((now - out) / (1000*60*60*24))
      return { ...r, status: diffDays <= 30 ? 'active' : 'non-active' }
    })
    res.json(data)
  } catch (err) {
    console.error(err)
    res.status(500).json({ success:false, message:'Gagal ambil data' })
  }
})

// delete user (dan API terkait)
app.delete('/admin/user/:id', authMiddleware, async (req, res) => {
  const userId = req.params.id
  const conn = connection
  try {
    // ambil key_id
    const [rows] = await conn.execute('SELECT key_id FROM User WHERE user_id = ?', [userId])
    if (rows.length === 0) return res.status(404).json({ success:false, message:'User tidak ditemukan' })
    const keyId = rows[0].key_id
    // hapus user, lalu API
    await conn.execute('DELETE FROM User WHERE user_id = ?', [userId])
    await conn.execute('DELETE FROM API WHERE key_id = ?', [keyId])
    res.json({ success:true })
  } catch (err) {
    console.error(err)
    res.status(500).json({ success:false, message:'Gagal menghapus' })
  }
})

async function connectDB() {
  try {
    connection = await mysql.createConnection(dbConfig)
    console.log('✅ Terhubung ke database MySQL')
  } catch (err) {
    console.error('❌ Gagal konek ke database:', err)
  }
}

app.listen(port, async () => {
  await connectDB()
  console.log(`🚀 Server berjalan di http://localhost:${port}`)
})