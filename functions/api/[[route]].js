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
    if (data.status === 'success') {
      return { country: data.country, code: data.countryCode, ip: data.query }
    }
  } catch (e) {}
  return null
}

// --- 核心：清洗引擎 ---
const cleanNodes = (nodes, globalParams, localParams) => {
  // 合并规则：优先使用本地规则，如果没有则使用全局
  // 注意：这里采用的是“合并生效”策略，还是“本地覆盖全局”？
  // 为了灵活，我们采用：先应用全局，再应用本地。
  
  const applyRules = (nodeList, params) => {
    if (!params) return nodeList
    let list = [...nodeList]

    // 1. 排除 (Exclude)
    if (params.exclude) {
      const excludes = params.exclude.split('\n').filter(k => k.trim())
      if (excludes.length > 0) {
        list = list.filter(node => !excludes.some(k => node.name.includes(k)))
      }
    }

    // 2. 包含 (Include) - 如果设置了，只保留匹配的
    if (params.include) {
      const includes = params.include.split('\n').filter(k => k.trim())
      if (includes.length > 0) {
        list = list.filter(node => includes.some(k => node.name.includes(k)))
      }
    }

    // 3. 重命名 (Rename)
    if (params.rename) {
      const renames = params.rename.split('\n').filter(k => k.trim())
      renames.forEach(rule => {
        // 格式: 旧文本@新文本 (用@分隔)
        const parts = rule.split('@')
        if (parts.length === 2) {
          const [oldStr, newStr] = parts
          list.forEach(node => {
            // 支持简单的字符串替换
            node.name = node.name.split(oldStr).join(newStr)
          })
        }
      })
    }
    return list
  }

  let result = nodes
  if (globalParams) result = applyRules(result, globalParams)
  if (localParams) result = applyRules(result, localParams)
  
  return result
}

// --- 核心：节点解析 ---
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
        const b64 = trimLine.substring(8)
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
        try { name = decodeURIComponent(trimLine.substring(hashIndex + 1)) } 
        catch (e) { name = trimLine.substring(hashIndex + 1) }
      }
      nodes.push({ name: name, type: protocol, link: trimLine })
      continue
    }
  }
  
  // Fallback for YAML proxies names
  if (nodes.length === 0) {
     const nameRegex = /^\s*-\s*(?:name:|{\s*name:)\s*(.+?)(?:}|)\s*$/gm
     let match
     while ((match = nameRegex.exec(text)) !== null) {
         nodes.push({ name: match[1].trim(), type: 'clash', link: '' })
     }
  }

  return nodes
}

// --- 检测接口 (集成清洗逻辑) ---
app.post('/check', async (c) => {
  try {
    const { url, type, needNodes, params } = await c.req.json() // params 是该订阅的本地规则
    if (!url) return c.json({ success: false, error: '链接为空' })

    // 获取全局规则
    let globalParams = null
    try {
        const { results } = await c.env.DB.prepare("SELECT value FROM settings WHERE key = 'filter_config'").all()
        if (results.length > 0 && results[0].value) {
            globalParams = JSON.parse(results[0].value)
        }
    } catch(e) {}

    let resultData = { valid: false, nodeCount: 0, stats: null, location: null, nodes: [] }

    // >>> 场景1：自建节点
    if (type === 'node') {
      let nodeList = parseNodes(url)
      if (nodeList.length === 0) return c.json({ success: false, error: '未检测到有效节点' })
      
      // 应用清洗
      nodeList = cleanNodes(nodeList, globalParams, params)
      
      resultData.valid = true
      resultData.nodeCount = nodeList.length
      if (needNodes) resultData.nodes = nodeList

      try {
        const firstLink = nodeList[0]?.link
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

    // >>> 场景2：机场订阅
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
          raw_expire: info.expire
        }
      }
    }

    // 节点处理
    const text = (v2rayRes && v2rayRes.ok) ? await v2rayRes.text() : await clashRes.text()
    let nodeList = parseNodes(text)
    
    // 应用清洗 (关键步骤)
    nodeList = cleanNodes(nodeList, globalParams, params)

    resultData.valid = true
    resultData.nodeCount = nodeList.length
    if (needNodes) resultData.nodes = nodeList

    return c.json({ success: true, data: resultData })

  } catch (e) {
    return c.json({ success: false, error: e.message })
  }
})

// --- 列表 CRUD (支持 params) ---
app.get('/subs', async (c) => {
  if (!c.env.DB) return c.json({ error: 'DB未绑定' }, 500)
  const { results } = await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY sort_order ASC, id DESC").all()
  const data = results.map(item => {
    try { item.info = item.info ? JSON.parse(item.info) : null } catch(e) { item.info = null }
    try { item.params = item.params ? JSON.parse(item.params) : null } catch(e) { item.params = null }
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
  const qParams = []
  if (name !== undefined) { query += ", name = ?"; qParams.push(name); }
  if (url !== undefined) { query += ", url = ?"; qParams.push(url); }
  if (status !== undefined) { query += ", status = ?"; qParams.push(status); }
  if (type !== undefined) { query += ", type = ?"; qParams.push(type); }
  if (info !== undefined) { query += ", info = ?"; qParams.push(info ? JSON.stringify(info) : null); }
  if (params !== undefined) { query += ", params = ?"; qParams.push(params ? JSON.stringify(params) : null); }
  query += " WHERE id = ?"
  qParams.push(id)
  await c.env.DB.prepare(query).bind(...qParams).run()
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

// 设置
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
  for (const [key, value] of Object.entries(body)) {
      // 如果是对象，转JSON存
      const val = typeof value === 'object' ? JSON.stringify(value) : value
      batch.push(stmt.bind(key, val))
  }
  await c.env.DB.batch(batch)
  return c.json({ success: true })
})

app.post('/login', async (c) => {
  const { password } = await c.req.json()
  return (password === c.env.ADMIN_PASSWORD) ? c.json({ success: true }) : c.json({ success: false, error: '密码错误' }, 401)
})

export const onRequest = handle(app)
