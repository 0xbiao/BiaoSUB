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
    // 过滤掉内网IP和非域名格式
    if (!host || host.match(/^(127\.|192\.168\.|10\.|localhost)/)) return null;
    const res = await fetch(`http://ip-api.com/json/${host}?fields=status,country,countryCode,query`)
    const data = await res.json()
    if (data.status === 'success') {
      return { country: data.country, code: data.countryCode, ip: data.query }
    }
  } catch (e) {}
  return null
}

// 带重试和 UA 轮询的 Fetch
const fetchWithRetry = async (url, options = {}, retries = 1) => {
  const uas = [
    options.headers['User-Agent'], // 优先使用传入的 UA
    'Clash/1.0',                   // 备用1：Clash
    'v2rayNG/1.8.5',               // 备用2：v2rayNG
    'Mozilla/5.0'                  // 备用3：浏览器
  ];

  for (let i = 0; i <= retries; i++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // 15秒超时
      
      // 每次重试尝试切换 UA，增加成功率
      const currentUA = uas[i % uas.length];
      const currentHeaders = { ...options.headers, 'User-Agent': currentUA };

      const res = await fetch(url, { ...options, headers: currentHeaders, signal: controller.signal })
      clearTimeout(timeoutId);
      
      if (res.ok || res.status === 404 || res.status === 401) return res
    } catch (err) {
      if (i === retries) throw err
    }
  }
}

const safeBase64Decode = (str) => {
  try {
    let clean = str.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/')
    while (clean.length % 4) clean += '='
    const binary = atob(clean)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    return new TextDecoder('utf-8').decode(bytes)
  } catch (e) { return null }
}

const safeStr = (str) => {
    if (!str) return '""'
    const s = String(str).trim()
    if (/[:#\[\]\{\},&*!|>'%@]/.test(s) || /^\s|\s$/.test(s)) return JSON.stringify(s)
    return s
}

// --- 3. 核心：全能节点解析器 (大幅增强兼容性) ---

// YAML 解析器：不依赖 "name" 在首位，只要是 list item 就抓取
const parseYamlProxies = (content) => {
    const nodes = []
    try {
        // 1. 定位 proxies 块
        const proxyBlockMatch = content.match(/^(proxies|Proxy):\s*\n/m)
        if (!proxyBlockMatch) return nodes

        const startIndex = proxyBlockMatch.index + proxyBlockMatch[0].length
        let blockContent = content.substring(startIndex)
        
        // 截断后续的 proxy-groups 等其他块，防止解析越界
        const nextBlockMatch = blockContent.match(/^(proxy-groups|rules|rule-providers):/m)
        if (nextBlockMatch) {
            blockContent = blockContent.substring(0, nextBlockMatch.index)
        }

        // 2. 按 YAML 列表项符号 "-" 分割
        // 匹配行首的 - (加空格)，这代表一个数组项的开始
        const items = blockContent.split(/^\s*-\s+/m)
        
        for (let i = 1; i < items.length; i++) {
            const itemBlock = items[i]
            
            // 提取函数：在当前块中查找 key: value
            const extract = (key) => {
                // 匹配 key: value，允许 value 被引号包裹
                const regex = new RegExp(`^\\s*${key}:\\s*(?:['"](.*?)['"]|(.*?))\\s*(?:$|#)`, 'm')
                const match = itemBlock.match(regex)
                if (!match) return undefined
                return (match[1] || match[2]).trim()
            }

            const type = extract('type')
            if (!type || !['vmess', 'vless', 'trojan', 'ss', 'hysteria2', 'tuic'].includes(type)) continue
            
            const server = extract('server')
            const port = extract('port')
            if (!server || !port) continue

            const node = {
                name: extract('name') || `${type}-${server}`, // 兜底名称
                type: type, server: server, port: port,
                cipher: extract('cipher'), uuid: extract('uuid'), password: extract('password'),
                tls: extract('tls') === 'true', "skip-cert-verify": extract('skip-cert-verify') === 'true',
                servername: extract('servername') || extract('sni'), network: extract('network'),
                "ws-opts": undefined
            }

            // 提取 ws-opts path/headers
            if (node.network === 'ws') {
                const path = extract('path')
                // headers 比较复杂，简单尝试提取 Host
                const hostMatch = itemBlock.match(/headers:\s*\{?\s*Host:\s*(.*?)(?:\}|$|\n)/i) || itemBlock.match(/Host:\s*(.*?)(?:\}|$|\n)/i)
                node["ws-opts"] = {
                    path: path || '/',
                    headers: { Host: hostMatch ? hostMatch[1].trim().replace(/['"]/g, '') : '' }
                }
            }
            node.link = `${type}://${node.server}:${node.port}#${encodeURIComponent(node.name)}`
            nodes.push(node)
        }
    } catch(e) {
        console.error('YAML parsing failed:', e)
    }
    return nodes
}

// 通用解析入口
const parseNodesCommon = (text) => {
    if (!text) return []
    
    let contentToParse = text
    
    // 1. 尝试 Base64 解码 (针对 v2rayN 格式或 Base64 包裹的 YAML)
    // 如果不包含 :// 且看似 Base64，先解码
    if (!text.includes('://') && !text.includes('proxies:')) {
        const decoded = safeBase64Decode(text)
        if (decoded) {
            contentToParse = decoded
        }
    }

    // 2. 检查是否为 YAML (Clash 格式)
    if (contentToParse.includes('proxies:') || contentToParse.includes('Proxy:')) {
        const yamlNodes = parseYamlProxies(contentToParse)
        if (yamlNodes.length > 0) return yamlNodes
    }

    // 3. 逐行解析 (Standard Links)
    const lines = contentToParse.split(/\r?\n/)
    const nodes = []
    const regex = /^(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//i

    for (const line of lines) {
        const trimLine = line.trim()
        if (!trimLine) continue

        // VMess
        if (trimLine.startsWith('vmess://')) {
            try {
                const jsonStr = safeBase64Decode(trimLine.substring(8))
                const conf = JSON.parse(jsonStr)
                nodes.push({
                    name: conf.ps || 'vmess', type: 'vmess', link: trimLine,
                    server: conf.add, port: conf.port, uuid: conf.id, alterId: conf.aid||0, 
                    cipher: "auto", tls: conf.tls==="tls", servername: conf.host||"", 
                    network: conf.net||"tcp", "ws-opts": conf.net==="ws" ? { path: conf.path||"/", headers: { Host: conf.host||"" } } : undefined
                })
            } catch (e) {}
            continue
        }

        // 其他协议
        if (trimLine.match(regex)) {
            const protocol = trimLine.split(':')[0].toLowerCase()
            let name = `${protocol}节点`
            const hashIndex = trimLine.lastIndexOf('#')
            if (hashIndex !== -1) {
                try { name = decodeURIComponent(trimLine.substring(hashIndex + 1)) } catch (e) { name = trimLine.substring(hashIndex + 1) }
            }
            let details = {}
            try {
                const urlObj = new URL(trimLine);
                const params = urlObj.searchParams;
                details = {
                    server: urlObj.hostname, port: urlObj.port, uuid: urlObj.username, password: urlObj.username || urlObj.password,
                    sni: params.get("sni")||"", servername: params.get("sni")||"", "skip-cert-verify": true,
                    network: params.get("type")||"tcp", tls: params.get("security")==="tls",
                    cipher: protocol === 'ss' ? urlObj.username : "auto",
                    "ws-opts": params.get("type")==="ws" ? { path: params.get("path")||"/", headers: { Host: params.get("host")||"" } } : undefined
                }
                // SS 旧版兼容
                if (protocol === 'ss' && !trimLine.includes('@')) {
                     // 尝试 Base64 解码部分
                     try {
                        const ssBody = trimLine.split('://')[1].split('#')[0]
                        const decodedSS = safeBase64Decode(ssBody)
                        if(decodedSS && decodedSS.includes(':') && decodedSS.includes('@')) {
                            // aes-256-gcm:pass@ip:port
                            const [methodPass, serverPort] = decodedSS.split('@')
                            const [method, pass] = methodPass.split(':')
                            const [ip, port] = serverPort.split(':')
                            details.server = ip; details.port = port; details.cipher = method; details.password = pass;
                        }
                     } catch(e) {}
                }
            } catch(e) {}
            nodes.push({ name: name, type: protocol, link: trimLine, ...details })
        }
    }
    return nodes
}

// --- 4. API 路由 ---

// 共享：获取所有节点
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
            while (allNodes.some(n => n.name === finalName)) finalName = `${node.name} ${counter++}`
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
        
        let template = ""
        try {
            const { results } = await c.env.DB.prepare("SELECT content FROM templates WHERE is_default = 1 LIMIT 1").all()
            if (results.length > 0) template = results[0].content
        } catch(e) {}
        
        if (!template || template.trim() === "") template = `port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: false
bind-address: '*'
mode: rule
log-level: info
ipv6: true
find-process-mode: strict
external-controller: '127.0.0.1:9090'
profile:
  store-selected: true
  store-fake-ip: true
unified-delay: true
tcp-concurrent: true
rule-providers:
  private_ip:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt"
    path: ./ruleset/private.yaml
    interval: 86400
  cn_ip:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt"
    path: ./ruleset/cncidr.yaml
    interval: 86400
  cn_domain:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cn.txt"
    path: ./ruleset/cn.yaml
    interval: 86400
  geolocation-!cn:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"
    path: ./ruleset/proxy.yaml
    interval: 86400
ntp:
  enable: true
  write-to-system: false
  server: ntp.aliyun.com
  port: 123
  interval: 30
dns:
  enable: true
  respect-rules: true
  use-system-hosts: true
  prefer-h3: false
  listen: '0.0.0.0:1053'
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  use-hosts: true
  fake-ip-filter:
    - +.lan
    - +.local
    - localhost.ptlogin2.qq.com
    - +.msftconnecttest.com
    - +.msftncsi.com
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  proxy-server-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - 'https://1.0.0.1/dns-query'
    - 'https://9.9.9.10/dns-query'
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
  strict-route: false
  dns-hijack:
    - 'any:53'
  device: SakuraiTunnel
  endpoint-independent-nat: true

proxies:
  <BIAOSUB_PROXIES>

proxy-groups:
  - name: 主代理
    type: select
    proxies:
      <BIAOSUB_GROUP_ALL>

rules:
  - RULE-SET,private_ip,DIRECT,no-resolve
  - RULE-SET,cn_ip,DIRECT
  - RULE-SET,cn_domain,DIRECT
  - RULE-SET,geolocation-!cn,主代理
  - MATCH,主代理`

        const { allNodes, sourceCount } = await getAllNodes(c.env)
        if (allNodes.length === 0) {
             allNodes.push({name: `⛔️ 无节点 (源:${sourceCount})`, type: "ss", server: "127.0.0.1", port: 80, cipher: "aes-128-gcm", password: "error"})
        }

        const proxiesYaml = allNodes.map(p => {
            let yaml = `  - name: ${safeStr(p.name)}\n    type: ${p.type}\n    server: ${safeStr(p.server)}\n    port: ${p.port}\n`;
            if(p.uuid) yaml += `    uuid: ${safeStr(p.uuid)}\n`;
            if(p.cipher) yaml += `    cipher: ${p.cipher}\n`;
            if(p.password) yaml += `    password: ${safeStr(p.password)}\n`;
            if(p.tls !== undefined) yaml += `    tls: ${p.tls}\n`;
            if(p["skip-cert-verify"] !== undefined) yaml += `    skip-cert-verify: ${p["skip-cert-verify"]}\n`;
            if(p.servername) yaml += `    servername: ${safeStr(p.servername)}\n`;
            if(p.sni) yaml += `    sni: ${safeStr(p.sni)}\n`;
            if(p.network) yaml += `    network: ${p.network}\n`;
            if(p.alterId !== undefined) yaml += `    alterId: ${p.alterId}\n`;
            if(p["ws-opts"]) {
                yaml += `    ws-opts:\n      path: ${safeStr(p["ws-opts"].path)}\n`;
                if(p["ws-opts"].headers && p["ws-opts"].headers.Host) {
                    yaml += `      headers:\n        Host: ${safeStr(p["ws-opts"].headers.Host)}\n`;
                }
            }
            return yaml;
        }).join("\n");

        const groupsYaml = allNodes.map(n => `      - ${safeStr(n.name)}`).join("\n");
        const finalYaml = template.replace(/^\s*<BIAOSUB_PROXIES>/gm, proxiesYaml).replace(/^\s*<BIAOSUB_GROUP_ALL>/gm, groupsYaml);

        return c.text(finalYaml, 200, { 'Content-Type': 'text/yaml; charset=utf-8', 'Content-Disposition': 'attachment; filename="biaosub_clash.yaml"' })
    } catch(e) { return c.text(`Error: ${e.message}`, 500) }
})

// B. Base64 订阅
app.get('/subscribe/base64', async (c) => {
    try {
        const token = c.req.query('token')
        if (token !== c.env.ADMIN_PASSWORD) return c.text('Unauthorized', 401)
        const { allNodes } = await getAllNodes(c.env)
        const links = allNodes.map(n => n.link || "").filter(l => l !== "")
        const finalString = links.join('\n')
        const base64Result = btoa(encodeURIComponent(finalString).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode('0x' + p1)));
        return c.text(base64Result, 200, { 'Content-Type': 'text/plain; charset=utf-8' })
    } catch(e) { return c.text(`Error: ${e.message}`, 500) }
})

// C. Check 接口 (增强流量提取 & 0节点兜底)
app.post('/check', async (c) => {
  try {
    const { url, type, needNodes, ua } = await c.req.json()
    if (!url) return c.json({ success: false, error: '链接为空' })
    let resultData = { valid: false, nodeCount: 0, stats: null, location: null, nodes: [] }
    const userAgent = ua || 'v2rayNG/1.8.5'

    if (type === 'node') {
      const nodeList = parseNodesCommon(url)
      if (nodeList.length === 0) return c.json({ success: false, error: '未检测到有效节点' })
      resultData.valid = true; resultData.nodeCount = nodeList.length; if (needNodes) resultData.nodes = nodeList
      try { if (nodeList[0].server) resultData.location = await getGeoInfo(nodeList[0].server) } catch(e) {}
      return c.json({ success: true, data: resultData })
    }

    const validRes = await fetchWithRetry(url, { headers: { 'User-Agent': userAgent } })
    if (!validRes || !validRes.ok) return c.json({ success: false, error: `连接失败: ${validRes?validRes.status:0}` })

    // 流量提取 (增强版: 不区分大小写，处理多余空格)
    const h = validRes.headers
    // 遍历 headers 寻找包含 userinfo 的 key
    let infoHeader = null;
    h.forEach((val, key) => {
        if (key.toLowerCase().includes('userinfo')) infoHeader = val;
    });
    
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

    const text = await validRes.text()
    const nodeList = parseNodesCommon(text)
    
    // 如果流量正常但节点为0，尝试用 Base64 再次强制解码一次 (应对极个别奇葩格式)
    if (nodeList.length === 0 && resultData.stats) {
         const retryNodes = parseNodesCommon(safeBase64Decode(text));
         if (retryNodes.length > 0) nodeList.push(...retryNodes);
    }

    resultData.valid = true; 
    resultData.nodeCount = nodeList.length; 
    if (needNodes) resultData.nodes = nodeList
    
    return c.json({ success: true, data: resultData })

  } catch (e) { return c.json({ success: false, error: e.message }) }
})

// D. CRUD 接口
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
