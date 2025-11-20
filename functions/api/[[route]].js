import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono().basePath('/api')

// 1. 允许跨域 (CORS)
app.use('/*', cors())

// 2. 核心鉴权中间件 (防盗门)
app.use('/*', async (c, next) => {
  // 如果是登录接口，直接放行
  if (c.req.path.endsWith('/login')) {
    return await next()
  }

  // 获取请求头里的 Authorization 字段
  const authHeader = c.req.header('Authorization')
  
  // 获取环境变量里的密码
  const correctPassword = c.env.ADMIN_PASSWORD

  // 如果没有设置密码，为了安全，默认拒绝所有操作
  if (!correctPassword) {
    return c.json({ success: false, error: '服务端未设置 ADMIN_PASSWORD 环境变量' }, 500)
  }

  // 比对密码
  if (authHeader !== correctPassword) {
    return c.json({ success: false, error: '未授权: 密码错误' }, 401)
  }

  // 密码正确，放行
  await next()
})

app.onError((err, c) => {
  console.error(`${err}`)
  return c.json({ error: err.message }, 500)
})

// --- 登录接口 ---
app.post('/login', async (c) => {
  const body = await c.req.json()
  const { password } = body
  
  if (password === c.env.ADMIN_PASSWORD) {
    return c.json({ success: true, message: '登录成功' })
  } else {
    return c.json({ success: false, error: '密码错误' }, 401)
  }
})

// --- 之前的业务接口 (无需改动逻辑，因为被中间件保护了) ---

// 获取列表
app.get('/subs', async (c) => {
  if (!c.env.DB) return c.json({ error: 'DB未绑定' }, 500)
  const { results } = await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY created_at DESC").all()
  return c.json({ success: true, data: results })
})

// 添加
app.post('/subs', async (c) => {
  const { name, url, type } = await c.req.json()
  const { success } = await c.env.DB.prepare("INSERT INTO subscriptions (name, url, type) VALUES (?, ?, ?)").bind(name, url, type || 'subscription').run()
  return success ? c.json({ success: true }) : c.json({ success: false }, 500)
})

// 删除
app.delete('/subs/:id', async (c) => {
  const id = c.req.param('id')
  await c.env.DB.prepare("DELETE FROM subscriptions WHERE id = ?").bind(id).run()
  return c.json({ success: true })
})

// 更新
app.put('/subs/:id', async (c) => {
  const id = c.req.param('id')
  const body = await c.req.json()
  const { name, url, status, type } = body
  let query = "UPDATE subscriptions SET updated_at = CURRENT_TIMESTAMP"
  const params = []
  if (name !== undefined) { query += ", name = ?"; params.push(name); }
  if (url !== undefined) { query += ", url = ?"; params.push(url); }
  if (status !== undefined) { query += ", status = ?"; params.push(status); }
  if (type !== undefined) { query += ", type = ?"; params.push(type); }
  query += " WHERE id = ?"
  params.push(id)
  await c.env.DB.prepare(query).bind(...params).run()
  return c.json({ success: true })
})

// 获取设置
app.get('/settings', async (c) => {
  const { results } = await c.env.DB.prepare("SELECT key, value FROM settings").all()
  const settings = {}
  results.forEach(row => { settings[row.key] = row.value })
  return c.json({ success: true, data: settings })
})

// 保存设置
app.post('/settings', async (c) => {
  const body = await c.req.json()
  const stmt = c.env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)")
  const batch = []
  for (const [key, value] of Object.entries(body)) batch.push(stmt.bind(key, value))
  await c.env.DB.batch(batch)
  return c.json({ success: true })
})

export const onRequest = handle(app)
