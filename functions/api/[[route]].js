import { Hono } from 'hono'
import { cors } from 'hono/cors'

const app = new Hono().basePath('/api')

app.use('/*', cors())

app.onError((err, c) => {
  console.error(`${err}`)
  return c.json({ error: err.message }, 500)
})

// 1. 获取所有订阅/节点
app.get('/subs', async (c) => {
  try {
    // 检查数据库绑定是否存在
    if (!c.env.DB) {
      throw new Error('数据库未绑定，请在 Cloudflare Pages 设置中绑定 D1 数据库，变量名为 DB')
    }
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM subscriptions ORDER BY created_at DESC"
    ).all()
    return c.json({ success: true, data: results })
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

// 2. 添加订阅或节点
app.post('/subs', async (c) => {
  try {
    const body = await c.req.json()
    const { name, url, type } = body

    if (!name || !url) {
      return c.json({ success: false, error: '名称和链接不能为空' }, 400)
    }

    // 允许的类型：general(通用订阅), v2ray(订阅), clash(订阅), node(单节点)
    const safeType = type || 'general'

    const { success } = await c.env.DB.prepare(
      "INSERT INTO subscriptions (name, url, type) VALUES (?, ?, ?)"
    ).bind(name, url, safeType).run()

    if (success) {
      return c.json({ success: true, message: '添加成功' })
    } else {
      return c.json({ success: false, error: '数据库写入失败' }, 500)
    }
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

// 3. 删除
app.delete('/subs/:id', async (c) => {
  const id = c.req.param('id')
  try {
    await c.env.DB.prepare(
      "DELETE FROM subscriptions WHERE id = ?"
    ).bind(id).run()
    return c.json({ success: true, message: '删除成功' })
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

// 4. 更新
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
    return c.json({ success: true, message: '更新成功' })
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

export default app
