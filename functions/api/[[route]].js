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

// 获取 IP 地理位置
const getGeoInfo = async (host) => {
  try {
    const res = await fetch(`http://ip-api.com/json/${host}?fields=status,country,countryCode,query`)
    const data = await res.json()
    if (data.status === 'success') {
      return { country: data.country, code: data.countryCode, ip: data.query }
    }
  } catch (e) {}
  return null
}

// --- 检测接口 (修复计数逻辑) ---
app.post('/check', async (c) => {
  try {
    const { url, type } = await c.req.json()
    if (!url) return c.json({ success: false, error: '链接为空' })

    let resultData = {
      valid: false,
      nodeCount: 0,
      stats: null,
      location: null
    }

    // >>> 场景1：自建节点
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

      if (validCount === 0) return c.json({ success: false, error: '未检测到有效节点链接' })
      
      resultData.valid = true
      resultData.nodeCount = validCount
      if (firstHost) resultData.location = await getGeoInfo(firstHost)
      
      return c.json({ success: true, data: resultData })
    }

    // >>> 场景2：机场订阅 (核心修改)
    // 使用 v2rayNG User-Agent，强制获取 Base64 格式，避免获取到难以解析的 Clash YAML
    const res = await fetch(url, { 
      headers: { 
        'User-Agent': 'v2rayNG/1.8.5' 
      } 
    })

    if (!res.ok) return c.json({ success: false, error: `HTTP ${res.status}` })

    // 解析流量头
    const infoHeader = res.headers.get('subscription-userinfo')
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
          percent: Math.min(100, Math.round((used / info.total) * 100))
        }
      }
    }

    // 解析节点数 (增强版)
    const text = await res.text()
    
    try {
        // 1. 尝试 Base64 解码 (先去除所有空格和换行，防止解码失败)
        const cleanText = text.replace(/\s/g, '')
        const decoded = atob(cleanText.replace(/-/g, '+').replace(/_/g, '/'))
        
        // 2. 解码成功，按行分割并计数
        // 过滤掉空行，且必须包含协议头 (://) 或者是 ss:// 这种
        resultData.nodeCount = decoded.split('\n')
            .map(line => line.trim())
            .filter(line => line && line.match(/^[a-z0-9]+:\/\//i))
            .length
            
    } catch (e) {
        // 3. 如果解码失败 (说明可能是明文列表，或者机场强制返回了 YAML)
        console.log('Base64 decode failed, trying text mode')
        
        // 尝试直接按行统计链接
        const linkCount = text.split('\n')
            .filter(line => line.trim().match(/^[a-z0-9]+:\/\//i))
            .length
            
        if (linkCount > 0) {
            resultData.nodeCount = linkCount
        } else {
            // 4. 最后尝试匹配 YAML 格式 (以防万一)
            // 统计 "- name:" 的出现次数
            const yamlMatches = text.match(/^\s*-\s*(name:|{\s*name:)/gm)
            if (yamlMatches) {
                resultData.nodeCount = yamlMatches.length
            }
        }
    }
    
    resultData.valid = true
    return c.json({ success: true, data: resultData })

  } catch (e) {
    return c.json({ success: false, error: e.message })
  }
})

// --- 列表 CRUD ---

app.get('/subs', async (c) => {
  if (!c.env.DB) return c.json({ error: 'DB未绑定' }, 500)
  const { results } = await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY created_at DESC").all()
  const data = results.map(item => {
    try { item.info = item.info ? JSON.parse(item.info) : null } catch(e) { item.info = null }
    return item
  })
  return c.json({ success: true, data })
})

app.post('/subs', async (c) => {
  const { name, url, type, info } = await c.req.json()
  const infoStr = info ? JSON.stringify(info) : null
  const { success } = await c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info) VALUES (?, ?, ?, ?)").bind(name, url, type || 'subscription', infoStr).run()
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
