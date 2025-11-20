import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono().basePath('/api')

app.use('/*', cors())

// --- 鉴权中间件 ---
app.use('/*', async (c, next) => {
  if (c.req.path.endsWith('/login')) return await next()
  const authHeader = c.req.header('Authorization')
  const correctPassword = c.env.ADMIN_PASSWORD
  if (!correctPassword) return c.json({ success: false, error: '未设置环境变量 ADMIN_PASSWORD' }, 500)
  if (authHeader !== correctPassword) return c.json({ success: false, error: '密码错误' }, 401)
  await next()
})

app.onError((err, c) => {
  console.error(`${err}`)
  return c.json({ error: err.message }, 500)
})

// --- 辅助函数：格式化流量 ---
const formatBytes = (bytes) => {
  if (!bytes || isNaN(bytes)) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

// --- 辅助函数：格式化日期 ---
const formatDate = (timestamp) => {
  if (!timestamp || isNaN(timestamp)) return '长期有效'
  // 有些机场返回的是秒，有些是毫秒，做个判断
  const date = new Date(timestamp.toString().length === 10 ? timestamp * 1000 : timestamp)
  return date.toLocaleDateString()
}

// --- 新增：检测接口 ---
app.post('/check', async (c) => {
  try {
    const { url, type } = await c.req.json()
    
    if (!url) return c.json({ success: false, error: '链接为空' })

    // 1. 如果是自建节点 (Node)
    if (type === 'node') {
      // 简单的格式校验
      if (!url.match(/^(vmess|vless|ss|trojan|hysteria|http|https):\/\//)) {
        return c.json({ success: false, error: '链接协议不支持 (必须是 vmess:// 等)' })
      }
      // 注意：CF Worker 无法进行真实的 ICMP Ping，只能做格式检查
      return c.json({ 
        success: true, 
        data: { 
          valid: true, 
          message: '链接格式正确 (Worker环境不支持Ping测速)' 
        } 
      })
    }

    // 2. 如果是机场订阅 (Subscription)
    // 伪装 User-Agent 防止被屏蔽
    const res = await fetch(url, {
      headers: { 'User-Agent': 'Clash/1.0' }
    })

    if (!res.ok) {
      return c.json({ success: false, error: `连接失败: HTTP ${res.status}` })
    }

    // 解析 Subscription-Userinfo 头
    const infoHeader = res.headers.get('subscription-userinfo')
    let stats = null
    
    if (infoHeader) {
      // 格式通常为: upload=123; download=456; total=789; expire=123456
      const info = {}
      infoHeader.split(';').forEach(part => {
        const [key, value] = part.trim().split('=')
        if(key && value) info[key] = Number(value)
      })
      
      if (info.total) {
        const used = (info.upload || 0) + (info.download || 0)
        stats = {
          used: formatBytes(used),
          total: formatBytes(info.total),
          expire: formatDate(info.expire),
          remaining: formatBytes(info.total - used)
        }
      }
    }

    // 计算节点数量 (简单统计行数或 vmess:// 出现的次数)
    const text = await res.text()
    let nodeCount = 0
    try {
        // 尝试 Base64 解码
        const decoded = atob(text.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''))
        nodeCount = decoded.split('\n').filter(line => line.trim().length > 0).length
    } catch (e) {
        // 如果解码失败，可能就是明文，直接算行数
        nodeCount = text.split('\n').filter(line => line.trim().length > 0).length
    }

    return c.json({ 
      success: true, 
      data: { 
        valid: true,
        stats: stats, // 如果没有头信息，这里可能是 null
        nodeCount: nodeCount
      } 
    })

  } catch (e) {
    return c.json({ success: false, error: e.message })
  }
})

// --- 原有 CRUD 接口 (保持不变) ---
app.get('/subs', async (c) => {
  if (!c.env.DB) return c.json({ error: 'DB未绑定' }, 500)
  const { results } = await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY created_at DESC").all()
  return c.json({ success: true, data: results })
})
app.post('/subs', async (c) => {
  const { name, url, type } = await c.req.json()
  const { success } = await c.env.DB.prepare("INSERT INTO subscriptions (name, url, type) VALUES (?, ?, ?)").bind(name, url, type || 'subscription').run()
  return success ? c.json({ success: true }) : c.json({ success: false }, 500)
})
app.delete('/subs/:id', async (c) => {
  const id = c.req.param('id')
  await c.env.DB.prepare("DELETE FROM subscriptions WHERE id = ?").bind(id).run()
  return c.json({ success: true })
})
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
app.get('/settings', async (c) => {
  const { results } = await c.env.DB.prepare("SELECT key, value FROM settings").all()
  const settings = {}
  results.forEach(row => { settings[row.key] = row.value })
  return c.json({ success: true, data: settings })
})
app.post('/settings', async (c) => {
  const body = await c.req.json()
  const stmt = c.env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)")
  const batch = []
  for (const [key, value] of Object.entries(body)) batch.push(stmt.bind(key, value))
  await c.env.DB.batch(batch)
  return c.json({ success: true })
})
app.post('/login', async (c) => {
  const { password } = await c.req.json()
  return (password === c.env.ADMIN_PASSWORD) ? c.json({ success: true }) : c.json({ success: false, error: '密码错误' }, 401)
})

export const onRequest = handle(app)
