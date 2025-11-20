import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono().basePath('/api')

app.use('/*', cors())

app.onError((err, c) => {
  console.error(`${err}`)
  return c.json({ error: err.message }, 500)
})

// --- 订阅/节点管理接口 ---

// 1. 获取列表
app.get('/subs', async (c) => {
  if (!c.env.DB) return c.json({ error: 'DB未绑定' }, 500)
  try {
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM subscriptions ORDER BY created_at DESC"
    ).all()
    return c.json({ success: true, data: results })
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

// 2. 添加
app.post('/subs', async (c) => {
  try {
    const body = await c.req.json()
    const { name, url, type } = body
    const finalType = type || 'subscription'
    const { success } = await c.env.DB.prepare(
      "INSERT INTO subscriptions (name, url, type) VALUES (?, ?, ?)"
    ).bind(name, url, finalType).run()
    if (success) return c.json({ success: true, message: 'Added' })
    return c.json({ success: false, error: 'DB Error' }, 500)
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

// 3. 删除
app.delete('/subs/:id', async (c) => {
  const id = c.req.param('id')
  try {
    await c.env.DB.prepare("DELETE FROM subscriptions WHERE id = ?").bind(id).run()
    return c.json({ success: true })
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

// 4. 更新状态/信息
app.put('/subs/:id', async (c) => {
  const id = c.req.param('id')
  const body = await c.req.json()
  const { name, url, status, type } = body
  try {
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
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

// --- 全局设置接口 (新增) ---

// 5. 获取所有设置
app.get('/settings', async (c) => {
  try {
    const { results } = await c.env.DB.prepare("SELECT key, value FROM settings").all()
    // 转换成对象格式 { key: value }
    const settings = {}
    results.forEach(row => { settings[row.key] = row.value })
    return c.json({ success: true, data: settings })
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

// 6. 保存设置
app.post('/settings', async (c) => {
  try {
    const body = await c.req.json()
    const stmt = c.env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)")
    const batch = []
    
    // 遍历提交的 JSON 对象，批量更新
    for (const [key, value] of Object.entries(body)) {
        batch.push(stmt.bind(key, value))
    }
    
    await c.env.DB.batch(batch)
    return c.json({ success: true, message: 'Settings saved' })
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

export const onRequest = handle(app)
