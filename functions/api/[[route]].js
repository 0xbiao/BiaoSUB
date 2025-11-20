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
    if (data.status === 'success') {
      return { country: data.country, code: data.countryCode, ip: data.query }
    }
  } catch (e) {}
  return null
}

// 带重试的 Fetch
const fetchWithRetry = async (url, options = {}, retries = 2) => {
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await fetch(url, options)
      if (res.ok) return res
      if (res.status === 404 || res.status === 401) return res
      if (i === retries) return res
    } catch (err) {
      if (i === retries) throw err
    }
  }
}

// --- 核心：节点解析函数 (用于预览和检测) ---
const parseNodes = (text) => {
  const nodes = []
  
  // 尝试 Base64 解码
  let decodedText = text
  try {
    const cleanText = text.replace(/\s/g, '')
    decodedText = atob(cleanText.replace(/-/g, '+').replace(/_/g, '/'))
  } catch (e) {
    // 如果解码失败，假设原文就是明文
  }

  const lines = decodedText.split('\n')
  const regex = /^(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//i

  for (const line of lines) {
    const trimLine = line.trim()
    if (!trimLine) continue

    // 1. 处理 vmess
    if (trimLine.startsWith('vmess://')) {
      try {
        const b64 = trimLine.substring(8).replace(/-/g, '+').replace(/_/g, '/')
        const jsonStr = atob(b64)
        const config = JSON.parse(jsonStr)
        nodes.push({ name: config.ps || 'vmess节点', type: 'vmess', link: trimLine })
      } catch (e) {
        nodes.push({ name: 'vmess节点(解析失败)', type: 'vmess', link: trimLine })
      }
      continue
    }

    // 2. 处理其他协议
    if (trimLine.match(regex)) {
      const protocol = trimLine.split(':')[0]
      let name = `${protocol}节点`
      const hashIndex = trimLine.lastIndexOf('#')
      if (hashIndex !== -1) {
        try {
          name = decodeURIComponent(trimLine.substring(hashIndex + 1))
        } catch (e) {
          name = trimLine.substring(hashIndex + 1)
        }
      }
      nodes.push({ name: name, type: protocol, link: trimLine })
      continue
    }
  }

  // 3. 尝试简单的 Clash YAML 提取 (仅提取名称用于预览)
  if (nodes.length === 0) {
    const nameRegex = /^\s*-\s*(?:name:|{\s*name:)\s*(.+?)(?:}|)\s*$/gm
    let match
    while ((match = nameRegex.exec(text)) !== null) {
        nodes.push({ name: match[1].trim(), type: 'clash', link: '' })
    }
  }

  return nodes
}

// --- API 路由 ---

// 1. 检测链接 / 获取节点列表
app.post('/check', async (c) => {
  try {
    const { url, type, needNodes, ua } = await c.req.json()
    if (!url) return c.json({ success: false, error: '链接为空' })

    let resultData = { valid: false, nodeCount: 0, stats: null, location: null, nodes: [] }
    // 使用前端传来的 UA，如果没有则用默认
    const userAgent = ua || 'v2rayNG/1.8.5'

    // >>> 场景1：自建节点 (Node)
    if (type === 'node') {
      // 直接解析 URL 字段的内容
      const nodeList = parseNodes(url)
      if (nodeList.length === 0) return c.json({ success: false, error: '未检测到有效节点' })
      
      resultData.valid = true
      resultData.nodeCount = nodeList.length
      if (needNodes) resultData.nodes = nodeList

      // 尝试获取第一个节点的 IP 位置
      try {
        const firstLink = nodeList[0].link
        if (firstLink) {
           const temp = firstLink.split('://')[1]
           const atPart = temp.split('@')
           const addressPart = atPart.length > 1 ? atPart[1] : atPart[0]
           const host = addressPart.split(':')[0].split('/')[0].split('?')[0]
           if (host) resultData.location = await getGeoInfo(host)
        }
      } catch(e) {}

      return c.json({ success: true, data: resultData })
    }

    // >>> 场景2：机场订阅 (Subscription)
    // 并发请求：尝试 Clash UA 和 自定义/v2ray UA
    const [clashRes, v2rayRes] = await Promise.all([
      fetchWithRetry(url, { headers: { 'User-Agent': 'Clash/1.0' } }).catch(e => null),
      fetchWithRetry(url, { headers: { 'User-Agent': userAgent } }).catch(e => null)
    ])
    
    const validRes = clashRes || v2rayRes
    if (!validRes || !validRes.ok) return c.json({ success: false, error: `连接失败` })

    // 解析流量信息
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
          raw_expire: info.expire
        }
      }
    }

    // 解析节点内容
    const text = (v2rayRes && v2rayRes.ok) ? await v2rayRes.text() : await clashRes.text()
    const nodeList = parseNodes(text)
    
    resultData.valid = true
    resultData.nodeCount = nodeList.length
    if (needNodes) resultData.nodes = nodeList

    return c.json({ success: true, data: resultData })

  } catch (e) {
    return c.json({ success: false, error: e.message })
  }
})

// 2. 获取订阅列表
app.get('/subs', async (c) => {
  if (!c.env.DB) return c.json({ error: 'DB未绑定' }, 500)
  const { results } = await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY sort_order ASC, id DESC").all()
  const data = results.map(item => {
    try { item.info = item.info ? JSON.parse(item.info) : null } catch(e) { item.info = null }
    try { item.params = item.params ? JSON.parse(item.params) : {} } catch(e) { item.params = {} }
    return item
  })
  return c.json({ success: true, data })
})

// 3. 添加订阅
app.post('/subs', async (c) => {
  const { name, url, type, info, params } = await c.req.json()
  const infoStr = info ? JSON.stringify(info) : null
  const paramsStr = params ? JSON.stringify(params) : null
  const { success } = await c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, params, sort_order) VALUES (?, ?, ?, ?, ?, 0)").bind(name, url, type || 'subscription', infoStr, paramsStr).run()
  return success ? c.json({ success: true }) : c.json({ success: false }, 500)
})

// 4. 更新订阅
app.put('/subs/:id', async (c) => {
  const id = c.req.param('id')
  const body = await c.req.json()
  const { name, url, status, type, info, params } = body
  
  let query = "UPDATE subscriptions SET updated_at = CURRENT_TIMESTAMP"
  const sqlParams = []
  
  if (name !== undefined) { query += ", name = ?"; sqlParams.push(name); }
  if (url !== undefined) { query += ", url = ?"; sqlParams.push(url); }
  if (status !== undefined) { query += ", status = ?"; sqlParams.push(status); }
  if (type !== undefined) { query += ", type = ?"; sqlParams.push(type); }
  if (info !== undefined) { query += ", info = ?"; sqlParams.push(info ? JSON.stringify(info) : null); }
  if (params !== undefined) { query += ", params = ?"; sqlParams.push(params ? JSON.stringify(params) : null); }
  
  query += " WHERE id = ?"
  sqlParams.push(id)
  
  await c.env.DB.prepare(query).bind(...sqlParams).run()
  return c.json({ success: true })
})

// 5. 删除订阅
app.delete('/subs/:id', async (c) => {
  const id = c.req.param('id')
  await c.env.DB.prepare("DELETE FROM subscriptions WHERE id = ?").bind(id).run()
  return c.json({ success: true })
})

// 6. 排序
app.post('/sort', async (c) => {
  const { ids } = await c.req.json()
  if (!Array.isArray(ids)) return c.json({ success: false, error: 'Invalid data' })
  const stmt = c.env.DB.prepare("UPDATE subscriptions SET sort_order = ? WHERE id = ?")
  const batch = ids.map((id, index) => stmt.bind(index, id))
  await c.env.DB.batch(batch)
  return c.json({ success: true })
})

// 7. 导入备份
app.post('/backup/import', async (c) => {
  const { items } = await c.req.json()
  if (!Array.isArray(items)) return c.json({ success: false, error: 'Invalid data' })
  const stmt = c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, params, status, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)")
  const batch = items.map(item => {
    const infoStr = item.info ? JSON.stringify(item.info) : null
    const paramsStr = item.params ? JSON.stringify(item.params) : null
    return stmt.bind(item.name, item.url, item.type || 'subscription', infoStr, paramsStr, item.status ?? 1, item.sort_order ?? 0)
  })
  try { await c.env.DB.batch(batch); return c.json({ success: true }) } catch(e) { return c.json({ success: false, error: e.message }) }
})

// 8. 获取设置
app.get('/settings', async (c) => {
  const { results } = await c.env.DB.prepare("SELECT key, value FROM settings").all()
  const settings = {}
  results.forEach(row => { settings[row.key] = row.value })
  return c.json({ success: true, data: settings })
})

// 9. 保存设置
app.post('/settings', async (c) => {
  const body = await c.req.json()
  const stmt = c.env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)")
  const batch = []
  for (const [key, value] of Object.entries(body)) batch.push(stmt.bind(key, value))
  await c.env.DB.batch(batch)
  return c.json({ success: true })
})

// 10. 登录
app.post('/login', async (c) => {
  const { password } = await c.req.json()
  return (password === c.env.ADMIN_PASSWORD) ? c.json({ success: true }) : c.json({ success: false, error: '密码错误' }, 401)
})

export const onRequest = handle(app)
