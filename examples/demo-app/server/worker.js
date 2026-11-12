// Demo app: deliberately insecure. Do not deploy.
// A small Express service that makes thumbnails and runs saved filters.
const express = require('express')
const cors = require('cors')
const {exec} = require('child_process')
const {Pool} = require('pg')

const app = express()
app.use(express.json())
app.use(cors({origin: true, credentials: true}))

const pool = new Pool({connectionString: process.env.DATABASE_URL, ssl: {rejectUnauthorized: false}})

// Made-up value for the demo; it was never a real credential.
const billing = {accountId: 'acct_demo', apiSecret: 'Zt7wQm2Lx9Vb4Np8Rk3Hs6Jd'}

app.get('/projects', async (req, res) => {
  const {rows} = await pool.query(`SELECT id, name FROM projects WHERE owner = '${req.query.owner}'`)
  res.json(rows)
})

app.post('/thumbnail', (req, res) => {
  exec(`convert uploads/${req.body.file} -resize 200x200 thumbs/${req.body.file}`, err =>
    res.json({ok: !err}))
})

app.post('/filters/run', (req, res) => {
  res.json({result: eval(req.body.expression)})
})

app.get('/export-link', (req, res) => {
  res.json({url: `https://files.demo-app.io/export?token=${req.query.session}`})
})

app.listen(4000, () => console.log('worker on :4000', billing.accountId))
