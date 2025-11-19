import { Hono } from 'hono'
import { cors } from 'hono/cors'

const app = new Hono().basePath('/api')

// 允许跨域，方便调试和前端调用
app.use('/*', cors())

// 错误处理
app.onError((err, c) => {
  console.error(`${err}`)
  return c.json({ error: err.message }, 500)
})

// 1. 获取所有订阅 (GET /api/subs)
app.get('/subs', async (c) => {
  try {
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM subscriptions ORDER BY created_at DESC"
    ).all()
    return c.json({ success: true, data: results })
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

// 2. 添加订阅 (POST /api/subs)
app.post('/subs', async (c) => {
  try {
    const body = await c.req.json()
    const { name, url, type } = body

    if (!name || !url) {
      return c.json({ success: false, error: '名称和链接不能为空' }, 400)
    }

    const { success } = await c.env.DB.prepare(
      "INSERT INTO subscriptions (name, url, type) VALUES (?, ?, ?)"
    ).bind(name, url, type || 'general').run()

    if (success) {
      return c.json({ success: true, message: '添加成功' })
    } else {
      return c.json({ success: false, error: '数据库写入失败' }, 500)
    }
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

// 3. 删除订阅 (DELETE /api/subs/:id)
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

// 4. 更新订阅状态/信息 (PUT /api/subs/:id)
app.put('/subs/:id', async (c) => {
  const id = c.req.param('id')
  const body = await c.req.json()
  const { name, url, status } = body

  try {
    // 动态构建 SQL，允许只更新部分字段
    let query = "UPDATE subscriptions SET updated_at = CURRENT_TIMESTAMP"
    const params = []

    if (name !== undefined) {
      query += ", name = ?"
      params.push(name)
    }
    if (url !== undefined) {
      query += ", url = ?"
      params.push(url)
    }
    if (status !== undefined) {
      query += ", status = ?"
      params.push(status)
    }

    query += " WHERE id = ?"
    params.push(id)

    await c.env.DB.prepare(query).bind(...params).run()
    return c.json({ success: true, message: '更新成功' })
  } catch (e) {
    return c.json({ success: false, error: e.message }, 500)
  }
})

export default app
