import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono().basePath('/api')

app.use('/*', cors())

// --- 1. 鉴权中间件 ---
app.use('/*', async (c, next) => {
  const path = c.req.path
  // 放行登录接口和订阅接口
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
    const res = await fetch(`http://ip-api.com/json/${host}?fields=status,country,countryCode,query`)
    const data = await res.json()
    if (data.status === 'success') {
      return { country: data.country, code: data.countryCode, ip: data.query }
    }
  } catch (e) {}
  return null
}

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

const safeAtob = (str) => {
  try {
    const clean = str.replace(/\s/g, '')
    if (!clean.includes('://')) {
        const padding = clean.length % 4;
        const padded = padding > 0 ? clean + '='.repeat(4 - padding) : clean;
        return atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
    }
  } catch (e) {}
  return null
}

const safeBtoa = (str) => {
  try {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode('0x' + p1)))
  } catch (e) { return str }
}

// 智能字符串处理
const smartStr = (str) => {
    if (!str) return '""';
    const s = String(str).trim();
    if (/[:#\[\]\{\},&*!|>'%@]/.test(s) || /^\s|\s$/.test(s)) {
        return JSON.stringify(s);
    }
    return s;
}

// --- 3. 核心解析逻辑 ---
const parseNodesCommon = (text) => {
    const nodes = []
    if (!text) return nodes

    let decodedText = text
    try {
        const cleanText = text.replace(/\s/g, '')
        if (!cleanText.includes('://')) {
            const padding = cleanText.length % 4;
            const paddedText = padding > 0 ? cleanText + '='.repeat(4 - padding) : cleanText;
            decodedText = atob(paddedText.replace(/-/g, '+').replace(/_/g, '/'))
        }
    } catch (e) {}

    const lines = decodedText.split(/\r?\n/)
    const regex = /^(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//i

    for (const line of lines) {
        const trimLine = line.trim()
        if (!trimLine) continue

        // VMess
        if (trimLine.startsWith('vmess://')) {
            try {
                const b64 = trimLine.substring(8).replace(/-/g, '+').replace(/_/g, '/')
                const conf = JSON.parse(atob(b64))
                nodes.push({
                    name: conf.ps || 'vmess节点',
                    type: 'vmess',
                    link: trimLine, // 保留原始链接
                    server: conf.add, port: conf.port, uuid: conf.id, alterId: conf.aid || 0, cipher: "auto", tls: conf.tls === "tls", servername: conf.host || "", network: conf.net || "tcp", "ws-opts": conf.net === "ws" ? { path: conf.path || "/", headers: { Host: conf.host || "" } } : undefined
                })
            } catch (e) {
                 nodes.push({ name: 'vmess解析异常', type: 'vmess', link: trimLine })
            }
            continue
        }

        // 通用协议
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
                    server: urlObj.hostname,
                    port: urlObj.port,
                    uuid: urlObj.username,
                    password: urlObj.username || urlObj.password,
                    sni: params.get("sni") || "",
                    servername: params.get("sni") || "",
                    "skip-cert-verify": true,
                    network: params.get("type") || "tcp",
                    tls: params.get("security") === "tls",
                    cipher: protocol === 'ss' ? urlObj.username : "auto",
                    "ws-opts": params.get("type") === "ws" ? { path: params.get("path") || "/", headers: { Host: params.get("host") || "" } } : undefined
                }
                if (protocol === 'ss' && !trimLine.includes('@')) {
                     details.cipher = "aes-256-gcm"; details.password = "dummy";
                }
            } catch(e) {}

            nodes.push({ name: name, type: protocol, link: trimLine, ...details })
            continue
        }
    }
    return nodes
}

// --- 4. API 路由 ---

// 共享：获取所有去重后的节点
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

        // 1. 获取模板 (若有自定义则用自定义，否则用最新内置模板)
        let template = ""
        try {
            const { results } = await c.env.DB.prepare("SELECT content FROM templates WHERE is_default = 1 LIMIT 1").all()
            if (results.length > 0) template = results[0].content
        } catch(e) {}
        
        // 最新兜底模板
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

        // 2. 获取节点
        const { allNodes, sourceCount } = await getAllNodes(c.env)

        if (allNodes.length === 0) {
             allNodes.push({name: `⛔️ 无节点 (源:${sourceCount})`, type: "ss", server: "127.0.0.1", port: 80, cipher: "aes-128-gcm", password: "error"})
        }

        // 3. 生成 YAML
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

// B. Base64 通用订阅接口 (新增)
app.get('/subscribe/base64', async (c) => {
    try {
        const token = c.req.query('token')
        if (token !== c.env.ADMIN_PASSWORD) return c.text('Unauthorized', 401)
        if (!c.env.DB) return c.text('DB Error', 500)

        const { allNodes } = await getAllNodes(c.env)
        
        // 提取所有原始链接 (link 字段在 parseNodesCommon 中已保留)
        // 如果 link 字段丢失，尝试简单重建 (仅限 V2RayN 识别的)
        const links = allNodes.map(n => n.link || "").filter(l => l !== "")
        
        const finalString = links.join('\n')
        const base64Result = safeBtoa(finalString)

        return c.text(base64Result, 200, {
            'Content-Type': 'text/plain; charset=utf-8'
        })
    } catch(e) {
        return c.text(`Error: ${e.message}`, 500)
    }
})

// C. 其他接口 (保持完整)
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
