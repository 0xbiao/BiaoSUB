import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono().basePath('/api')

app.use('/*', cors())

// --- 1. 鉴权中间件 ---
app.use('/*', async (c, next) => {
  const path = c.req.path
  if (path.endsWith('/login') || path.includes('/subscribe')) return await next()
  
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

// --- 2. 工具函数 ---
const fetchWithRetry = async (url, options = {}, retries = 1) => {
  for (let i = 0; i <= retries; i++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // 15秒超时
      const res = await fetch(url, { ...options, signal: controller.signal })
      clearTimeout(timeoutId);
      if (res.ok || res.status === 404 || res.status === 401) return res
    } catch (err) { if (i === retries) throw err }
  }
}

const safeStr = (str) => JSON.stringify(str) // 安全处理 YAML 字符串

// --- 3. 核心节点解析逻辑 (增强版) ---
const parseNodesCommon = (text) => {
    const nodes = []
    if (!text) return nodes

    let decodedText = text
    // A. 尝试 Base64 解码
    try {
        // 移除所有空白字符
        const cleanText = text.replace(/\s/g, '')
        // 简单的正则判断是否包含非 url 字符
        if (!cleanText.includes('://')) {
            // 补全 Base64 padding
            const padding = cleanText.length % 4;
            const paddedText = padding > 0 ? cleanText + '='.repeat(4 - padding) : cleanText;
            decodedText = atob(paddedText.replace(/-/g, '+').replace(/_/g, '/'))
        }
    } catch (e) {}

    // B. 按行分割
    const lines = decodedText.split(/\r?\n/)
    const regex = /^(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//i

    for (const line of lines) {
        const trimLine = line.trim()
        if (!trimLine) continue

        // 1. VMess 特殊处理
        if (trimLine.startsWith('vmess://')) {
            try {
                const b64 = trimLine.substring(8).replace(/-/g, '+').replace(/_/g, '/')
                const conf = JSON.parse(atob(b64))
                nodes.push({
                    name: conf.ps || 'vmess节点',
                    type: 'vmess',
                    // 详细字段
                    server: conf.add, port: conf.port, uuid: conf.id, alterId: conf.aid || 0, cipher: "auto", tls: conf.tls === "tls", servername: conf.host || "", network: conf.net || "tcp", "ws-opts": conf.net === "ws" ? { path: conf.path || "/", headers: { Host: conf.host || "" } } : undefined
                })
            } catch (e) {
                 // 即使解析失败，也把原始链接存着，避免漏掉
                 nodes.push({ name: 'vmess解析异常', type: 'vmess', link: trimLine })
            }
            continue
        }

        // 2. 通用协议处理
        if (trimLine.match(regex)) {
            const protocol = trimLine.split(':')[0].toLowerCase()
            let name = `${protocol}节点`
            let details = {}
            
            // 提取名称 (#后面)
            const hashIndex = trimLine.lastIndexOf('#')
            if (hashIndex !== -1) {
                try { name = decodeURIComponent(trimLine.substring(hashIndex + 1)) } catch (e) { name = trimLine.substring(hashIndex + 1) }
            }

            // 提取关键参数 (用于 Clash 配置生成)
            try {
                const urlObj = new URL(trimLine);
                const params = urlObj.searchParams;
                details = {
                    server: urlObj.hostname,
                    port: urlObj.port,
                    uuid: urlObj.username,
                    password: urlObj.username || urlObj.password, // 兼容 ss/trojan
                    sni: params.get("sni") || "",
                    servername: params.get("sni") || "",
                    "skip-cert-verify": true,
                    network: params.get("type") || "tcp",
                    tls: params.get("security") === "tls",
                    cipher: protocol === 'ss' ? urlObj.username : "auto", // SS 特殊处理
                    "ws-opts": params.get("type") === "ws" ? { path: params.get("path") || "/", headers: { Host: params.get("host") || "" } } : undefined
                }
                
                // SS 协议特殊处理 (base64 user:pass)
                if (protocol === 'ss' && !trimLine.includes('@')) {
                     // 简单处理旧版 SS 链接，防止报错
                     details.cipher = "aes-256-gcm"; 
                     details.password = "dummy";
                }
            } catch(e) {}

            nodes.push({ name: name, type: protocol, link: trimLine, ...details })
            continue
        }
    }
    
    return nodes
}

// --- 4. API 路由 ---

app.get('/subscribe/clash', async (c) => {
    try {
        const token = c.req.query('token')
        if (token !== c.env.ADMIN_PASSWORD) return c.text('Unauthorized', 401)
        if (!c.env.DB) return c.text('DB Error', 500)

        // 1. 获取模板
        let template = ""
        try {
            const { results } = await c.env.DB.prepare("SELECT content FROM templates WHERE is_default = 1 LIMIT 1").all()
            if (results.length > 0) template = results[0].content
        } catch(e) {}
        if (!template) template = `port: 7890\nproxies:\n<BIAOSUB_PROXIES>\nproxy-groups:\n  - name: Proxy\n    type: select\n    proxies:\n<BIAOSUB_GROUP_ALL>\n`

        // 2. 获取订阅源
        const { results: subs } = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC").all()
        
        let allNodes = []
        let uniqueKeys = new Set()
        let sourceCount = 0

        for (const sub of subs) {
            sourceCount++;
            let rawContent = sub.type === 'node' ? sub.url : ""
            let params = {}
            try { params = sub.params ? JSON.parse(sub.params) : {} } catch(e) {}
            // 白名单：如果没选任何节点，则 allowedNames 为 null，代表全选
            const allowedNames = (params.include && params.include.length > 0) ? new Set(params.include) : null

            if (sub.type !== 'node') {
                try {
                    const res = await fetchWithRetry(sub.url, { headers: { 'User-Agent': params.ua || 'v2rayNG/1.8.5' } })
                    if (res && res.ok) rawContent = await res.text()
                } catch(e) {}
            }

            if (!rawContent) continue
            
            const nodes = parseNodesCommon(rawContent)
            
            for (const node of nodes) {
                // 修复：移除严格的协议检查，允许所有解析出的协议
                // if (!['vmess','vless'...].includes(node.type)) continue; 

                // 去重
                const key = `${node.server}:${node.port}`
                if (uniqueKeys.has(key)) continue
                
                // 过滤：只有当 allowedNames 存在(用户勾选了)且名字不在其中时，才过滤
                // 名字比对使用 trim() 防止空格干扰
                if (allowedNames && !allowedNames.has(node.name.trim())) continue

                // 名字去重
                let finalName = node.name.trim()
                let counter = 1
                while (allNodes.some(n => n.name === finalName)) {
                    finalName = `${node.name} ${counter++}`
                }
                node.name = finalName

                uniqueKeys.add(key)
                allNodes.push(node)
            }
        }

        // 如果最终没有节点，生成调试信息
        if (allNodes.length === 0) {
             const msg = `⚠️ 无节点 (源:${sourceCount})`;
             allNodes.push({name: msg, type: "ss", server: "127.0.0.1", port: 80, cipher: "aes-128-gcm", password: "error"})
        }

        // 3. 生成 YAML
        const proxiesYaml = allNodes.map(p => {
            let yaml = `  - name: ${safeStr(p.name)}\n    type: ${p.type}\n    server: ${safeStr(p.server)}\n    port: ${p.port}\n`;
            // 通用字段
            if(p.uuid) yaml += `    uuid: ${safeStr(p.uuid)}\n`;
            if(p.cipher) yaml += `    cipher: ${p.cipher}\n`;
            if(p.password) yaml += `    password: ${safeStr(p.password)}\n`;
            if(p.tls !== undefined) yaml += `    tls: ${p.tls}\n`;
            if(p["skip-cert-verify"] !== undefined) yaml += `    skip-cert-verify: ${p["skip-cert-verify"]}\n`;
            if(p.servername) yaml += `    servername: ${safeStr(p.servername)}\n`;
            if(p.sni) yaml += `    sni: ${safeStr(p.sni)}\n`;
            if(p.network) yaml += `    network: ${p.network}\n`;
            
            // 特殊处理
            if(p.alterId !== undefined) yaml += `    alterId: ${p.alterId}\n`; // vmess
            
            // ws-opts
            if(p["ws-opts"]) {
                yaml += `    ws-opts:\n      path: ${safeStr(p["ws-opts"].path)}\n`;
                if(p["ws-opts"].headers && p["ws-opts"].headers.Host) {
                    yaml += `      headers:\n        Host: ${safeStr(p["ws-opts"].headers.Host)}\n`;
                }
            }
            return yaml;
        }).join("\n");

        const groupsYaml = allNodes.map(n => `      - ${safeStr(n.name)}`).join("\n");

        const finalYaml = template
            .replace(/<BIAOSUB_PROXIES>/g, proxiesYaml)
            .replace(/<BIAOSUB_GROUP_ALL>/g, groupsYaml)

        return c.text(finalYaml, 200, {
            'Content-Type': 'text/yaml; charset=utf-8',
            'Content-Disposition': 'attachment; filename="biaosub_clash.yaml"'
        })

    } catch(e) {
        return c.text(`Internal Error: ${e.message}`, 500)
    }
})

// --- 其他接口保持不变 (复制原逻辑) ---
app.post('/check', async (c) => {
  try {
    const { url, type, needNodes, ua } = await c.req.json()
    if (!url) return c.json({ success: false, error: '链接为空' })
    let resultData = { valid: false, nodeCount: 0, stats: null, location: null, nodes: [] }
    const userAgent = ua || 'v2rayNG/1.8.5'

    if (type === 'node') {
      const nodeList = parseNodesCommon(url)
      if (nodeList.length === 0) return c.json({ success: false, error: '未检测到有效节点' })
      resultData.valid = true
      resultData.nodeCount = nodeList.length
      if (needNodes) resultData.nodes = nodeList
      try {
        const firstLink = nodeList[0].link
        if (firstLink) {
           let host = ''
           if (firstLink.includes('@')) host = firstLink.split('@')[1].split(':')[0]
           else if (firstLink.includes('://')) host = firstLink.split('://')[1].split(':')[0]
           if (host) resultData.location = await getGeoInfo(host)
        }
      } catch(e) {}
      return c.json({ success: true, data: resultData })
    }
    const [clashRes, v2rayRes] = await Promise.all([
      fetchWithRetry(url, { headers: { 'User-Agent': 'Clash/1.0' } }).catch(e => null),
      fetchWithRetry(url, { headers: { 'User-Agent': userAgent } }).catch(e => null)
    ])
    const validRes = clashRes || v2rayRes
    if (!validRes || !validRes.ok) return c.json({ success: false, error: `连接失败: ${validRes?validRes.status:0}` })
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
          raw_used: used,
          raw_total: info.total
        }
      }
    }
    const text = (v2rayRes && v2rayRes.ok) ? await v2rayRes.text() : await clashRes.text()
    const nodeList = parseNodesCommon(text)
    resultData.valid = true
    resultData.nodeCount = nodeList.length
    if (needNodes) resultData.nodes = nodeList
    return c.json({ success: true, data: resultData })
  } catch (e) { return c.json({ success: false, error: e.message }) }
})

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
  const stmt = c.env.DB.prepare("UPDATE subscriptions SET sort_order = ? WHERE id = ?")
  const batch = ids.map((id, index) => stmt.bind(index, id))
  await c.env.DB.batch(batch)
  return c.json({ success: true })
})
app.post('/backup/import', async (c) => {
  const { items } = await c.req.json()
  const stmt = c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, params, status, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)")
  const batch = items.map(item => {
    const infoStr = item.info ? JSON.stringify(item.info) : null
    const paramsStr = item.params ? JSON.stringify(item.params) : null
    return stmt.bind(item.name, item.url, item.type || 'subscription', infoStr, paramsStr, item.status ?? 1, item.sort_order ?? 0)
  })
  try { await c.env.DB.batch(batch); return c.json({ success: true }) } catch(e) { return c.json({ success: false, error: e.message }) }
})
app.get('/settings', async (c) => {
  if (!c.env.DB) return c.json({ success: false, error: 'DB Missing' }, 500)
  try { const { results } = await c.env.DB.prepare("SELECT key, value FROM settings").all(); const settings = {}; results.forEach(row => { settings[row.key] = row.value }); return c.json({ success: true, data: settings }) } catch(e) { return c.json({ success: true, data: {} }) }
})
app.post('/settings', async (c) => {
  const body = await c.req.json()
  const stmt = c.env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)")
  const batch = []; for (const [key, value] of Object.entries(body)) batch.push(stmt.bind(key, value)); await c.env.DB.batch(batch)
  return c.json({ success: true })
})
app.get('/template/default', async (c) => {
    const { results } = await c.env.DB.prepare("SELECT content FROM templates WHERE is_default = 1").all()
    return c.json({ success: true, data: results[0]?.content || "" })
})
app.post('/template/default', async (c) => {
    const { content } = await c.req.json()
    await c.env.DB.prepare("UPDATE templates SET content = ? WHERE is_default = 1").bind(content).run()
    return c.json({ success: true })
})
app.post('/login', async (c) => {
  const { password } = await c.req.json()
  return (password === c.env.ADMIN_PASSWORD) ? c.json({ success: true }) : c.json({ success: false, error: '密码错误' }, 401)
})

export const onRequest = handle(app)
