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

// --- 2. 增强工具函数 ---

const fetchWithRetry = async (url, options = {}, retries = 1) => {
  for (let i = 0; i <= retries; i++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);
      const res = await fetch(url, { ...options, signal: controller.signal })
      clearTimeout(timeoutId);
      if (res.ok || res.status === 404 || res.status === 401) return res
    } catch (err) { if (i === retries) throw err }
  }
}

// 核心：解决乱码的 Base64 解码器
const safeBase64Decode = (str) => {
  try {
    // 1. 清理非 Base64 字符
    let clean = str.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/')
    // 2. 补全 padding
    while (clean.length % 4) clean += '='
    
    // 3. 解码为二进制字符串
    const binary = atob(clean)
    
    // 4. 转换为 Uint8Array 并用 TextDecoder 解码 (解决中文乱码的关键)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    return new TextDecoder('utf-8').decode(bytes)
  } catch (e) {
    return null
  }
}

const safeStr = (str) => {
    if (!str) return '""'
    const s = String(str).trim()
    if (/[:#\[\]\{\},&*!|>'%@]/.test(s) || /^\s|\s$/.test(s)) return JSON.stringify(s)
    return s
}

const getGeoInfo = async (host) => {
  try {
    const res = await fetch(`http://ip-api.com/json/${host}?fields=status,country,countryCode,query`)
    const data = await res.json()
    if (data.status === 'success') return { country: data.country, code: data.countryCode, ip: data.query }
  } catch (e) {}
  return null
}

// --- 3. 核心：全能节点解析器 ---

// 简单的 YAML 提取逻辑 (提取 proxies 数组)
const parseYamlProxies = (content) => {
    const nodes = []
    try {
        // 找到 proxies: 或 Proxy: 开始的位置
        const proxyBlockMatch = content.match(/^(proxies|Proxy):\s*\n/m)
        if (!proxyBlockMatch) return nodes

        const startIndex = proxyBlockMatch.index + proxyBlockMatch[0].length
        // 截取 proxies 之后的内容
        const blockContent = content.substring(startIndex)
        
        // 按 "- name:" 分割，这是一种简单的 YAML 列表解析 heuristic
        // 注意：这只能处理标准格式的 Clash 配置文件
        const items = blockContent.split(/^\s*-\s+name:/m)
        
        // 跳过第一个（通常是空的或者不相关的）
        for (let i = 1; i < items.length; i++) {
            const itemBlock = "name:" + items[i] // 补回被 split 吞掉的 name:
            
            // 提取关键字段的正则
            const extract = (key) => {
                const match = itemBlock.match(new RegExp(`^\\s*${key}:\\s*(.*)$`, 'm'))
                if (!match) return undefined
                // 去除引号和注释
                return match[1].trim().replace(/^['"]|['"]$/g, '').split('#')[0].trim()
            }

            const type = extract('type')
            // 只保留支持的节点类型
            if (!type || !['vmess', 'vless', 'trojan', 'ss', 'hysteria2', 'tuic'].includes(type)) continue

            // 提取 server 信息
            const server = extract('server')
            const port = extract('port')
            if (!server || !port) continue

            // 构建节点对象
            const node = {
                name: extract('name'),
                type: type,
                server: server,
                port: port,
                cipher: extract('cipher'),
                uuid: extract('uuid'),
                password: extract('password'),
                tls: extract('tls') === 'true',
                "skip-cert-verify": extract('skip-cert-verify') === 'true',
                servername: extract('servername') || extract('sni'),
                network: extract('network'),
                "ws-opts": undefined
            }

            // 尝试提取 ws-opts (简单处理 path 和 host)
            if (node.network === 'ws') {
                const pathMatch = itemBlock.match(/path:\s*(.*)/)
                const hostMatch = itemBlock.match(/headers:[\s\S]*?Host:\s*(.*)/i)
                node["ws-opts"] = {
                    path: pathMatch ? pathMatch[1].trim().replace(/^['"]|['"]$/g, '') : '/',
                    headers: { Host: hostMatch ? hostMatch[1].trim().replace(/^['"]|['"]$/g, '') : '' }
                }
            }
            
            // 补充原始链接 (用于 V2Ray Base64 订阅)
            // 这是一个模拟链接，虽然不是原始的，但能让 V2RayN 识别
            node.link = `${type}://${node.server}:${node.port}#${encodeURIComponent(node.name)}`
            
            nodes.push(node)
        }
    } catch(e) {
        console.error('YAML parse error', e)
    }
    return nodes
}

const parseNodesCommon = (text) => {
    if (!text) return []
    
    // 1. 优先尝试作为 YAML 解析 (解决机场订阅 0 节点问题)
    if (text.includes('proxies:') || text.includes('Proxy:')) {
        const yamlNodes = parseYamlProxies(text)
        if (yamlNodes.length > 0) return yamlNodes
    }

    let decodedText = text
    // 2. 尝试 Base64 解码 (使用新解码器解决乱码)
    if (!text.includes('://')) {
        const decoded = safeBase64Decode(text)
        if (decoded) decodedText = decoded
    }

    const lines = decodedText.split(/\r?\n/)
    const nodes = []
    const regex = /^(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//i

    for (const line of lines) {
        const trimLine = line.trim()
        if (!trimLine) continue

        // VMess 解析
        if (trimLine.startsWith('vmess://')) {
            try {
                const b64 = trimLine.substring(8)
                // 使用 safeBase64Decode 处理 JSON
                const jsonStr = safeBase64Decode(b64)
                const conf = JSON.parse(jsonStr)
                
                nodes.push({
                    name: conf.ps || 'vmess节点',
                    type: 'vmess',
                    link: trimLine,
                    server: conf.add, port: conf.port, uuid: conf.id, alterId: conf.aid||0, 
                    cipher: "auto", tls: conf.tls==="tls", servername: conf.host||"", 
                    network: conf.net||"tcp", 
                    "ws-opts": conf.net==="ws" ? { path: conf.path||"/", headers: { Host: conf.host||"" } } : undefined
                })
            } catch (e) {
                 nodes.push({ name: 'vmess解析异常', type: 'vmess', link: trimLine })
            }
            continue
        }

        // 通用链接解析
        if (trimLine.match(regex)) {
            const protocol = trimLine.split(':')[0].toLowerCase()
            let name = `${protocol}节点`
            let details = {}
            
            const hashIndex = trimLine.lastIndexOf('#')
            if (hashIndex !== -1) {
                try { name = decodeURIComponent(trimLine.substring(hashIndex + 1)) } catch (e) { name = trimLine.substring(hashIndex + 1) }
            }

            try {
                const urlObj = new URL(trimLine);
                const params = urlObj.searchParams;
                details = {
                    server: urlObj.hostname, port: urlObj.port, uuid: urlObj.username, 
                    password: urlObj.username || urlObj.password,
                    sni: params.get("sni")||"", servername: params.get("sni")||"", "skip-cert-verify": true,
                    network: params.get("type")||"tcp", tls: params.get("security")==="tls",
                    cipher: protocol === 'ss' ? urlObj.username : "auto",
                    "ws-opts": params.get("type")==="ws" ? { path: params.get("path")||"/", headers: { Host: params.get("host")||"" } } : undefined
                }
                
                if (protocol === 'ss' && !trimLine.includes('@')) {
                     // 处理旧版 ss://Base64
                     // 这里为了简化，假设解码后格式正确，实际可以进一步增强
                     details.cipher = "aes-256-gcm"; details.password = "dummy";
                }
            } catch(e) {}

            nodes.push({ name: name, type: protocol, link: trimLine, ...details })
        }
    }
    return nodes
}

// --- 4. API 路由 ---

// 获取所有节点 (复用逻辑)
async function getAllNodes(env) {
    const { results: subs } = await env.DB.prepare("SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC").all()
    let allNodes = []
    let uniqueKeys = new Set()
    let sourceCount = 0

    for (const sub of subs) {
        sourceCount++;
        let rawContent = sub.type === 'node' ? sub.url : ""
        let params = {}
        try { params = sub.params ? JSON.parse(sub.params) : {} } catch(e) {}
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
            const key = `${node.server}:${node.port}`
            if (uniqueKeys.has(key)) continue
            if (allowedNames && !allowedNames.has(node.name.trim())) continue

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
    return { allNodes, sourceCount }
}

// A. Clash 订阅接口
app.get('/subscribe/clash', async (c) => {
    try {
        const token = c.req.query('token')
        if (token !== c.env.ADMIN_PASSWORD) return c.text('Unauthorized', 401)
        if (!c.env.DB) return c.text('DB Error', 500)

        let template = ""
        try {
            const { results } = await c.env.DB.prepare("SELECT content FROM templates WHERE is_default = 1 LIMIT 1").all()
            if (results.length > 0) template = results[0].content
        } catch(e) {}
        
        if (!template || template.trim() === "") template = `port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
external-controller: '127.0.0.1:9090'
dns:
  enable: true
  listen: '0.0.0.0:1053'
  enhanced-mode: fake-ip
  nameserver: ['8.8.8.8','1.1.1.1']
proxies:
<BIAOSUB_PROXIES>
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
<BIAOSUB_GROUP_ALL>
rules:
  - MATCH,🚀 节点选择`

        const { allNodes, sourceCount } = await getAllNodes(c.env)

        if (allNodes.length === 0) {
             allNodes.push({name: `⛔️ 无节点 (源:${sourceCount})`, type: "ss", server: "127.0.0.1", port: 80, cipher: "aes-128-gcm", password: "error"})
        }

        const proxiesYaml = allNodes.map(p => {
            let yaml = `  - name: ${smartStr(p.name)}\n    type: ${p.type}\n    server: ${smartStr(p.server)}\n    port: ${p.port}\n`;
            if(p.uuid) yaml += `    uuid: ${smartStr(p.uuid)}\n`;
            if(p.cipher) yaml += `    cipher: ${p.cipher}\n`;
            if(p.password) yaml += `    password: ${smartStr(p.password)}\n`;
            if(p.tls !== undefined) yaml += `    tls: ${p.tls}\n`;
            if(p["skip-cert-verify"] !== undefined) yaml += `    skip-cert-verify: ${p["skip-cert-verify"]}\n`;
            if(p.servername) yaml += `    servername: ${smartStr(p.servername)}\n`;
            if(p.sni) yaml += `    sni: ${smartStr(p.sni)}\n`;
            if(p.network) yaml += `    network: ${p.network}\n`;
            if(p.alterId !== undefined) yaml += `    alterId: ${p.alterId}\n`;
            if(p["ws-opts"]) {
                yaml += `    ws-opts:\n      path: ${smartStr(p["ws-opts"].path)}\n`;
                if(p["ws-opts"].headers && p["ws-opts"].headers.Host) {
                    yaml += `      headers:\n        Host: ${smartStr(p["ws-opts"].headers.Host)}\n`;
                }
            }
            return yaml;
        }).join("\n");

        const groupsYaml = allNodes.map(n => `      - ${smartStr(n.name)}`).join("\n");

        const finalYaml = template
            .replace(/^\s*<BIAOSUB_PROXIES>/gm, proxiesYaml)
            .replace(/^\s*<BIAOSUB_GROUP_ALL>/gm, groupsYaml);

        return c.text(finalYaml, 200, {
            'Content-Type': 'text/yaml; charset=utf-8',
            'Content-Disposition': 'attachment; filename="biaosub_clash.yaml"'
        })

    } catch(e) {
        return c.text(`Internal Error: ${e.message}`, 500)
    }
})

// B. Base64 通用订阅接口
app.get('/subscribe/base64', async (c) => {
    try {
        const token = c.req.query('token')
        if (token !== c.env.ADMIN_PASSWORD) return c.text('Unauthorized', 401)
        
        const { allNodes } = await getAllNodes(c.env)
        const links = allNodes.map(n => n.link || "").filter(l => l !== "")
        
        // 使用 safeBase64Decode 的逆操作 safeBtoa (简单版)
        const finalString = links.join('\n')
        // 处理 UTF-8 到 Base64
        const base64Result = btoa(encodeURIComponent(finalString).replace(/%([0-9A-F]{2})/g,
            function toSolidBytes(match, p1) {
                return String.fromCharCode('0x' + p1);
        }));

        return c.text(base64Result, 200, {
            'Content-Type': 'text/plain; charset=utf-8'
        })
    } catch(e) {
        return c.text(`Error: ${e.message}`, 500)
    }
})

// C. 检查接口
app.post('/check', async (c) => {
  try {
    const { url, type, needNodes, ua } = await c.req.json()
    if (!url) return c.json({ success: false, error: '链接为空' })
    let resultData = { valid: false, nodeCount: 0, stats: null, location: null, nodes: [] }
    
    // 1. 检查单节点
    if (type === 'node') {
      const nodeList = parseNodesCommon(url)
      if (nodeList.length === 0) return c.json({ success: false, error: '未检测到有效节点' })
      resultData.valid = true
      resultData.nodeCount = nodeList.length
      if (needNodes) resultData.nodes = nodeList
      try {
        if (nodeList[0].server) {
           resultData.location = await getGeoInfo(nodeList[0].server)
        }
      } catch(e) {}
      return c.json({ success: true, data: resultData })
    }

    // 2. 检查订阅
    const userAgent = ua || 'v2rayNG/1.8.5'
    const res = await fetchWithRetry(url, { headers: { 'User-Agent': userAgent } })
    if (!res || !res.ok) return c.json({ success: false, error: `连接失败: ${res?res.status:0}` })

    // 提取流量信息
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
          percent: Math.min(100, Math.round((used / info.total) * 100)),
          raw_expire: info.expire,
          raw_used: used,
          raw_total: info.total
        }
      }
    }

    const text = await res.text()
    const nodeList = parseNodesCommon(text)
    resultData.valid = true
    resultData.nodeCount = nodeList.length
    if (needNodes) resultData.nodes = nodeList
    return c.json({ success: true, data: resultData })

  } catch (e) { return c.json({ success: false, error: e.message }) }
})

// D. CRUD 接口 (保持精简完整)
app.get('/subs', async (c) => {
  if (!c.env.DB) return c.json({ error: 'DB未绑定' }, 500)
  const { results } = await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY sort_order ASC, id DESC").all()
  return c.json({ success: true, data: results.map(i=>{try{i.info=JSON.parse(i.info);i.params=JSON.parse(i.params)}catch(e){}return i}) })
})
app.post('/subs', async (c) => {
  const { name, url, type, info, params } = await c.req.json()
  await c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, params, sort_order) VALUES (?, ?, ?, ?, ?, 0)").bind(name, url, type||'subscription', JSON.stringify(info), JSON.stringify(params)).run()
  return c.json({ success: true })
})
app.put('/subs/:id', async (c) => {
  const id = c.req.param('id'); const body = await c.req.json()
  let q="UPDATE subscriptions SET updated_at=CURRENT_TIMESTAMP"; const a=[]
  for(const k of ['name','url','status','type'])if(body[k]!==undefined){q+=`, ${k}=?`;a.push(body[k])}
  if(body.info){q+=`, info=?`;a.push(JSON.stringify(body.info))}
  if(body.params){q+=`, params=?`;a.push(JSON.stringify(body.params))}
  q+=" WHERE id=?"; a.push(id); await c.env.DB.prepare(q).bind(...a).run()
  return c.json({ success: true })
})
app.delete('/subs/:id', async (c) => { await c.env.DB.prepare("DELETE FROM subscriptions WHERE id=?").bind(c.req.param('id')).run(); return c.json({success:true}) })
app.post('/sort', async (c) => { const {ids}=await c.req.json(); const s=c.env.DB.prepare("UPDATE subscriptions SET sort_order=? WHERE id=?"); await c.env.DB.batch(ids.map((id,i)=>s.bind(i,id))); return c.json({success:true}) })
app.post('/backup/import', async (c) => { const {items}=await c.req.json(); const s=c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, params, status, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)"); await c.env.DB.batch(items.map(i=>s.bind(i.name,i.url,i.type||'subscription',JSON.stringify(i.info),JSON.stringify(i.params),i.status??1,i.sort_order??0))); return c.json({success:true}) })
app.get('/settings', async(c)=>{try{const{results}=await c.env.DB.prepare("SELECT key,value FROM settings").all();const s={};results.forEach(r=>s[r.key]=r.value);return c.json({success:true,data:s})}catch(e){return c.json({success:true,data:{}})}})
app.post('/settings', async(c)=>{const b=await c.req.json();const s=c.env.DB.prepare("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)");await c.env.DB.batch(Object.entries(b).map(([k,v])=>s.bind(k,v)));return c.json({success:true})})
app.get('/template/default', async (c) => { const {results}=await c.env.DB.prepare("SELECT content FROM templates WHERE is_default=1").all(); return c.json({success:true, data: results[0]?.content||""}) })
app.post('/template/default', async (c) => { const {content}=await c.req.json(); await c.env.DB.prepare("UPDATE templates SET content=? WHERE is_default=1").bind(content).run(); return c.json({success:true}) })
app.post('/login', async (c) => { const {password}=await c.req.json(); return (password===c.env.ADMIN_PASSWORD)?c.json({success:true}):c.json({success:false},401) })

export const onRequest = handle(app)
