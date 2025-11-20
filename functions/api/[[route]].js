import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { handle } from 'hono/cloudflare-pages'
import { connect } from 'cloudflare:sockets'

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

// --- 核心：节点解析函数 ---
const parseNodes = (text) => {
  const nodes = []
  let decodedText = text
  try {
    const cleanText = text.replace(/\s/g, '')
    decodedText = atob(cleanText.replace(/-/g, '+').replace(/_/g, '/'))
  } catch (e) {}

  const lines = decodedText.split('\n')
  const regex = /^(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//i

  for (const line of lines) {
    const trimLine = line.trim()
    if (!trimLine) continue

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

    if (trimLine.match(regex)) {
      const protocol = trimLine.split(':')[0]
      let name = `${protocol}节点`
      const hashIndex = trimLine.lastIndexOf('#')
      if (hashIndex !== -1) {
        try { name = decodeURIComponent(trimLine.substring(hashIndex + 1)) } catch (e) { name = trimLine.substring(hashIndex + 1) }
      }
      nodes.push({ name: name, type: protocol, link: trimLine })
      continue
    }
  }
  
  if (nodes.length === 0) {
    const nameRegex = /^\s*-\s*(?:name:|{\s*name:)\s*(.+?)(?:}|)\s*$/gm
    let match
    while ((match = nameRegex.exec(text)) !== null) {
        nodes.push({ name: match[1].trim(), type: 'clash', link: '' })
    }
  }
  return nodes
}

// --- 辅助：从链接中提取 Host 和 Port 用于测试 ---
const parseNodeAddress = (link) => {
  try {
    let host = ''
    let port = 80

    if (link.startsWith('vmess://')) {
      const b64 = link.substring(8).replace(/-/g, '+').replace(/_/g, '/')
      const config = JSON.parse(atob(b64))
      host = config.add
      port = config.port
    } else {
      // 处理 vless://, trojan://, ss:// 等
      // 通用格式通常是: protocol://user@host:port... 或 protocol://host:port...
      // 先去掉 protocol://
      const temp = link.split('://')[1]
      // 去掉 # 及其后面的部分
      const cleanLink = temp.split('#')[0]
      // 去掉 ? 及其后面的部分 (query string)
      const cleanLinkNoQuery = cleanLink.split('?')[0]
      
      // 尝试寻找 @，如果有，取 @ 后面的部分
      let addressPart = cleanLinkNoQuery
      if (cleanLinkNoQuery.includes('@')) {
        addressPart = cleanLinkNoQuery.split('@')[1]
      }
      
      // 此时 addressPart 应该是 host:port
      // 注意 IPv6 格式 [::1]:80
      const lastColonIndex = addressPart.lastIndexOf(':')
      if (lastColonIndex !== -1) {
        host = addressPart.substring(0, lastColonIndex)
        // 去掉可能存在的 [] (IPv6)
        host = host.replace(/^\[|\]$/g, '')
        port = parseInt(addressPart.substring(lastColonIndex + 1))
      }
    }

    if (host && port && !isNaN(port)) {
      return { host, port }
    }
  } catch (e) {
    console.error('Address parse error:', e)
  }
  return null
}

// --- API 路由 ---

// 1. 节点真机连通性测试 (TCP Ping)
app.post('/test-node', async (c) => {
  const { link } = await c.req.json()
  if (!link) return c.json({ success: false, error: 'No link' })

  const address = parseNodeAddress(link)
  if (!address) return c.json({ success: false, error: 'Parse failed' })

  try {
    const start = Date.now()
    // 使用 Cloudflare Sockets 发起 TCP 连接
    const socket = connect({ hostname: address.host, port: address.port })
    const writer = socket.writable.getWriter()
    
    // 等待连接建立 (opened 是一个 Promise)
    await socket.opened
    
    const latency = Date.now() - start
    
    // 立即关闭连接
    await writer.close() 
    // socket.close() 在某些环境可能需要，但在 Workers 中 writer.close() 通常足够

    return c.json({ success: true, latency })
  } catch (e) {
    return c.json({ success: false, error: e.message, latency: -1 })
  }
})

// 2. 检测链接 / 获取节点列表
app.post('/check', async (c) => {
  try {
    const { url, type, needNodes, ua } = await c.req.json()
    if (!url) return c.json({ success: false, error: '链接为空' })

    let resultData = { valid: false, nodeCount: 0, stats: null, location: null, nodes: [] }
    const userAgent = ua || 'v2rayNG/1.8.5'

    // 自建节点
    if (type === 'node') {
      const nodeList = parseNodes(url)
      if (nodeList.length === 0) return c.json({ success: false, error: '未检测到有效节点' })
      resultData.valid = true
      resultData.nodeCount = nodeList.length
      if (needNodes) resultData.nodes = nodeList
      try {
        const firstLink = nodeList[0].link
        if (firstLink) {
           const temp = firstLink.split('://')[1]
           const host = temp.split('@').pop().split(':')[0].split('/')[0].split('?')[0]
           if (host) resultData.location = await getGeoInfo(host)
        }
      } catch(e) {}
      return c.json({ success: true, data: resultData })
    }

    // 订阅链接
    const [clashRes, v2rayRes] = await Promise.all([
      fetchWithRetry(url, { headers: { 'User-Agent': 'Clash/1.0' } }).catch(e => null),
      fetchWithRetry(url, { headers: { 'User-Agent': userAgent } }).catch(e => null)
    ])
    const validRes = clashRes || v2rayRes
    if (!validRes || !validRes.ok) return c.json({ success: false, error: `连接失败` })

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
          raw_expire: info.expire,
          raw_used: used, // 供前端图表使用
          raw_total: info.total // 供前端图表使用
        }
      }
    }

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

// CRUD 接口
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

app.post('/subs', async (c) => {
  const { name, url, type, info, params } = await c.req.json()
  const infoStr = info ? JSON.stringify(info) : null
  const paramsStr = params ? JSON.stringify(params) : null
  const { success } = await c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, params, sort_order) VALUES (?, ?, ?, ?, ?, 0)").bind(name, url, type || 'subscription', infoStr, paramsStr).run()
  return success ? c.json({ success: true }) : c.json({ success: false }, 500)
})

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

app.delete('/subs/:id', async (c) => {
  const id = c.req.param('id')
  await c.env.DB.prepare("DELETE FROM subscriptions WHERE id = ?").bind(id).run()
  return c.json({ success: true })
})

app.post('/sort', async (c) => {
  const { ids } = await c.req.json()
  if (!Array.isArray(ids)) return c.json({ success: false, error: 'Invalid data' })
  const stmt = c.env.DB.prepare("UPDATE subscriptions SET sort_order = ? WHERE id = ?")
  const batch = ids.map((id, index) => stmt.bind(index, id))
  await c.env.DB.batch(batch)
  return c.json({ success: true })
})

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
