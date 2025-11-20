import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono().basePath('/api')

app.use('/*', cors())

// --- 鉴权 ---
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

// --- 工具函数 ---
const formatBytes = (bytes) => {
  if (!bytes || isNaN(bytes)) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}
const formatDate = (timestamp) => {
  if (!timestamp || isNaN(timestamp)) return '长期'
  const date = new Date(timestamp.toString().length === 10 ? timestamp * 1000 : timestamp)
  return date.toLocaleDateString()
}
const getGeoInfo = async (host) => {
  try {
    const res = await fetch(`http://ip-api.com/json/${host}?fields=status,country,countryCode,query`)
    const data = await res.json()
    if (data.status === 'success') return { country: data.country, code: data.countryCode, ip: data.query }
  } catch (e) {}
  return null
}

// --- 业务接口 ---

// 检测接口 (保持双重探测)
app.post('/check', async (c) => {
  try {
    const { url, type } = await c.req.json()
    if (!url) return c.json({ success: false, error: '链接为空' })

    let resultData = { valid: false, nodeCount: 0, stats: null, location: null }

    // 自建节点
    if (type === 'node') {
      const lines = url.split('\n').filter(l => l.trim().length > 0)
      const regex = /^(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//
      let validCount = 0
      let firstHost = ''
      for (const line of lines) {
        if (line.match(regex)) {
          validCount++
          if (!firstHost) {
            try {
              const temp = line.split('://')[1]
              const atPart = temp.split('@')
              const addressPart = atPart.length > 1 ? atPart[1] : atPart[0]
              firstHost = addressPart.split(':')[0].split('/')[0].split('?')[0]
            } catch(e) {}
          }
        }
      }
      if (validCount === 0) return c.json({ success: false, error: '无效链接' })
      resultData.valid = true
      resultData.nodeCount = validCount
      if (firstHost) resultData.location = await getGeoInfo(firstHost)
      return c.json({ success: true, data: resultData })
    }

    // 机场订阅 (双重探测)
    const [clashRes, v2rayRes] = await Promise.all([
      fetch(url, { headers: { 'User-Agent': 'Clash/1.0' } }).catch(e => null),
      fetch(url, { headers: { 'User-Agent': 'v2rayNG/1.8.5' } }).catch(e => null)
    ])
    const validRes = clashRes || v2rayRes
    if (!validRes || !validRes.ok) return c.json({ success: false, error: `连接失败` })

    // 流量
    const infoHeader = (clashRes && clashRes.headers.get('subscription-userinfo')) || (v2rayRes && v2rayRes.headers.get('subscription-userinfo'))
    if (infoHeader) {
      const info = {}
      infoHeader.split(';').forEach(part => {
        const [key, value] = part.trim().split('=')
        if(key && value) info[key] = Number(value)
      })
      if (info.total) {
        const used = (info.upload || 0) + (info.download || 0)
        resultData.stats = {
          used: formatBytes(used),
          total: formatBytes(info.total),
          expire: formatDate(info.expire),
          percent: Math.min(100, Math.round((used / info.total) * 100)),
          raw_expire: info.expire // 存储原始时间戳用于排序或判断
        }
      }
    }

    // 节点计数
    const text = (v2rayRes && v2rayRes.ok) ? await v2rayRes.text() : await clashRes.text()
    try {
        const cleanText = text.replace(/\s/g, '')
        const decoded = atob(cleanText.replace(/-/g, '+').replace(/_/g, '/'))
        resultData.nodeCount = decoded.split('\n').map(l => l.trim()).filter(l => l && l.match(/^[a-z0-9]+:\/\//i)).length
    } catch (e) {
        const linkCount = text.split('\n').filter(l => l.trim().match(/^[a-z0-9]+:\/\//i)).length
        if (linkCount > 0) resultData.nodeCount = linkCount
        else {
            const yamlMatches = text.match(/^\s*-\s*(name:|{\s*name:)/gm)
            if (yamlMatches) resultData.nodeCount = yamlMatches.length
        }
    }
    resultData.valid = true
    return c.json({ success: true, data: resultData })
  } catch (e) { return c.json({ success: false, error: e.message }) }
})

// 列表 (按 sort_order 排序)
app.get('/subs', async (c) => {
  if (!c.env.DB) return c.json({ error: 'DB未绑定' }, 500)
  // 优先 sort_order 升序，其次 id 降序
  const { results } = await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY sort_order ASC, id DESC").all()
  const data = results.map(item => {
    try { item.info = item.info ? JSON.parse(item.info) : null } catch(e) { item.info = null }
    return item
  })
  return c.json({ success: true, data })
})

// 保存排序
app.post('/sort', async (c) => {
  const { ids } = await c.req.json()
  if (!Array.isArray(ids)) return c.json({ success: false, error: 'Invalid data' })
  
  const stmt = c.env.DB.prepare("UPDATE subscriptions SET sort_order = ? WHERE id = ?")
  const batch = ids.map((id, index) => stmt.bind(index, id))
  await c.env.DB.batch(batch)
  return c.json({ success: true })
})

// 批量导入
app.post('/backup/import', async (c) => {
  const { items } = await c.req.json()
  if (!Array.isArray(items)) return c.json({ success: false, error: 'Invalid data' })
  
  const stmt = c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, status, sort_order) VALUES (?, ?, ?, ?, ?, ?)")
  const batch = items.map(item => {
    // 兼容旧数据，重新生成
    const infoStr = item.info ? JSON.stringify(item.info) : null
    return stmt.bind(item.name, item.url, item.type || 'subscription', infoStr, item.status ?? 1, item.sort_order ?? 0)
  })
  
  try {
    await c.env.DB.batch(batch)
    return c.json({ success: true })
  } catch(e) {
    return c.json({ success: false, error: e.message })
  }
})

// 常规 CRUD
app.post('/subs', async (c) => {
  const { name, url, type, info } = await c.req.json()
  const infoStr = info ? JSON.stringify(info) : null
  // 新增时 sort_order 设为 0 (或者你想设为最大值排到最后也可以，这里设0排前面)
  const { success } = await c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, sort_order) VALUES (?, ?, ?, ?, 0)").bind(name, url, type || 'subscription', infoStr).run()
  return success ? c.json({ success: true }) : c.json({ success: false }, 500)
})

app.put('/subs/:id', async (c) => {
  const id = c.req.param('id')
  const body = await c.req.json()
  const { name, url, status, type, info } = body
  let query = "UPDATE subscriptions SET updated_at = CURRENT_TIMESTAMP"
  const params = []
  if (name !== undefined) { query += ", name = ?"; params.push(name); }
  if (url !== undefined) { query += ", url = ?"; params.push(url); }
  if (status !== undefined) { query += ", status = ?"; params.push(status); }
  if (type !== undefined) { query += ", type = ?"; params.push(type); }
  if (info !== undefined) { query += ", info = ?"; params.push(info ? JSON.stringify(info) : null); }
  query += " WHERE id = ?"
  params.push(id)
  await c.env.DB.prepare(query).bind(...params).run()
  return c.json({ success: true })
})

app.delete('/subs/:id', async (c) => {
  const id = c.req.param('id')
  await c.env.DB.prepare("DELETE FROM subscriptions WHERE id = ?").bind(id).run()
  return c.json({ success: true })
})

// 设置相关
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
