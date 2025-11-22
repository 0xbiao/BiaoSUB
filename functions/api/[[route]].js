import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono().basePath('/api')

app.use('/*', cors())

// --- 1. 鉴权 ---
app.use('/*', async (c, next) => {
  const path = c.req.path
  if (path.endsWith('/login') || path.includes('/subscribe')) return await next()
  const authHeader = c.req.header('Authorization')
  const correctPassword = c.env.ADMIN_PASSWORD
  if (!correctPassword) return c.json({ success: false, error: '未设置环境变量 ADMIN_PASSWORD' }, 500)
  if (authHeader !== correctPassword) return c.json({ success: false, error: '密码错误' }, 401)
  await next()
})

app.onError((err, c) => c.json({ error: err.message }, 500))

// --- 2. 增强工具函数 ---

const formatBytes = (bytes) => {
  if (!bytes || isNaN(bytes)) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

const formatDate = (timestamp) => {
  if (!timestamp || isNaN(timestamp)) return '长期'
  // 兼容秒和毫秒
  const date = new Date(timestamp.toString().length === 10 ? timestamp * 1000 : timestamp)
  return date.toLocaleDateString()
}

const getGeoInfo = async (host) => {
  try {
    if (!host || host.match(/^(127\.|192\.168\.|10\.|localhost)/)) return null;
    const res = await fetch(`http://ip-api.com/json/${host}?fields=status,country,countryCode,query`)
    const data = await res.json()
    if (data.status === 'success') return { country: data.country, code: data.countryCode, ip: data.query }
  } catch (e) {}
  return null
}

// 智能 Fetch：自动轮询 UA 直到获取到有效内容或流量信息
const fetchWithSmartUA = async (url) => {
  const userAgents = [
    'Clash/1.0', // 首选，很多机场对 Clash 友好
    'v2rayNG/1.8.5',
    'Quantumult%20X/1.0.30',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' // 兜底
  ];

  let lastRes = null;
  let bestInfo = null;

  for (const ua of userAgents) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10秒超时
      const res = await fetch(url, { 
          headers: { 'User-Agent': ua }, 
          signal: controller.signal 
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        lastRes = res;
        // 尝试提取流量信息
        const info = extractUserInfo(res.headers);
        if (info) {
            // 如果拿到了流量信息，直接返回这个响应，不用试了
            // 将 info 挂载到 res 对象上方便后续读取
            res.trafficInfo = info;
            return res; 
        }
      }
    } catch (e) {}
  }
  // 如果所有 UA 都没拿到流量信息，返回最后一次成功的响应（至少能拿到节点）
  return lastRes;
}

// 流量信息提取器 (超级兼容版)
const extractUserInfo = (headers) => {
    // 1. 尝试标准 Header (忽略大小写)
    let infoStr = null;
    headers.forEach((val, key) => {
        if (key.toLowerCase() === 'subscription-userinfo') infoStr = val;
    });

    if (!infoStr) return null;

    const info = {};
    infoStr.split(';').forEach(part => {
        const [key, value] = part.trim().split('=');
        if (key && value) info[key] = Number(value);
    });

    if (!info.total) return null;

    const used = (info.upload || 0) + (info.download || 0);
    return {
        used: formatBytes(used),
        total: formatBytes(info.total),
        expire: formatDate(info.expire),
        percent: Math.min(100, Math.round((used / info.total) * 100)),
        raw_expire: info.expire,
        raw_used: used,
        raw_total: info.total
    };
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

// --- 3. 节点解析 (支持 Base64, YAML, 纯文本列表) ---
const parseYamlProxies = (content) => {
    const nodes = []
    try {
        const proxyBlockMatch = content.match(/^(proxies|Proxy):\s*\n/m)
        if (!proxyBlockMatch) return nodes
        const startIndex = proxyBlockMatch.index + proxyBlockMatch[0].length
        let blockContent = content.substring(startIndex)
        const nextBlockMatch = blockContent.match(/^(proxy-groups|rules|rule-providers):/m)
        if (nextBlockMatch) blockContent = blockContent.substring(0, nextBlockMatch.index)
        
        const items = blockContent.split(/^\s*-\s+/m)
        for (let i = 1; i < items.length; i++) {
            const itemBlock = items[i]
            const extract = (key) => {
                const regex = new RegExp(`^\\s*${key}:\\s*(?:['"](.*?)['"]|(.*?))\\s*(?:$|#)`, 'm')
                const match = itemBlock.match(regex)
                return match ? (match[1] || match[2]).trim() : undefined
            }
            const type = extract('type')
            if (!type || !['vmess', 'vless', 'trojan', 'ss', 'hysteria2', 'tuic'].includes(type)) continue
            const server = extract('server')
            const port = extract('port')
            if (!server || !port) continue

            const node = {
                name: extract('name') || `${type}-${server}`, type, server, port,
                cipher: extract('cipher'), uuid: extract('uuid'), password: extract('password'),
                tls: extract('tls') === 'true', "skip-cert-verify": extract('skip-cert-verify') === 'true',
                servername: extract('servername') || extract('sni'), network: extract('network'), "ws-opts": undefined
            }
            if (node.network === 'ws') {
                const path = extract('path')
                const hostMatch = itemBlock.match(/headers:\s*\{?\s*Host:\s*(.*?)(?:\}|$|\n)/i)
                node["ws-opts"] = {
                    path: path || '/',
                    headers: { Host: hostMatch ? hostMatch[1].trim().replace(/['"]/g, '') : '' }
                }
            }
            node.link = `${type}://${node.server}:${node.port}#${encodeURIComponent(node.name)}`
            nodes.push(node)
        }
    } catch(e) {}
    return nodes
}

const parseNodesCommon = (text) => {
    if (!text) return []
    
    // 1. 优先 Base64 解码
    let decodedText = text
    if (!text.includes('://') && !text.includes('proxies:')) {
        const decoded = safeBase64Decode(text)
        if (decoded) decodedText = decoded
    }

    // 2. 尝试 YAML
    if (decodedText.includes('proxies:') || decodedText.includes('Proxy:')) {
        const yamlNodes = parseYamlProxies(decodedText)
        if (yamlNodes.length > 0) return yamlNodes
    }

    // 3. 纯文本/Base64列表解析
    const lines = decodedText.split(/\r?\n/)
    const nodes = []
    const regex = /^(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//i

    for (const line of lines) {
        const trimLine = line.trim()
        if (!trimLine) continue

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
                if (protocol === 'ss' && !trimLine.includes('@')) {
                     details.cipher = "aes-256-gcm"; details.password = "dummy";
                }
            } catch(e) {}
            nodes.push({ name: name, type: protocol, link: trimLine, ...details })
        }
    }
    return nodes
}

// --- 4. API 路由 ---

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
                // 使用智能 UA 轮询获取内容
                const res = await fetchWithSmartUA(sub.url);
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

// A. Clash 订阅
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

// C. Check 接口 (核心更新：自动轮询 UA)
app.post('/check', async (c) => {
  try {
    const { url, type, needNodes } = await c.req.json()
    if (!url) return c.json({ success: false, error: '链接为空' })
    let resultData = { valid: false, nodeCount: 0, stats: null, location: null, nodes: [] }

    // 1. 检查单节点
    if (type === 'node') {
      const nodeList = parseNodesCommon(url)
      if (nodeList.length === 0) return c.json({ success: false, error: '未检测到有效节点' })
      resultData.valid = true; resultData.nodeCount = nodeList.length; if (needNodes) resultData.nodes = nodeList
      try { if (nodeList[0].server) resultData.location = await getGeoInfo(nodeList[0].server) } catch(e) {}
      return c.json({ success: true, data: resultData })
    }

    // 2. 检查订阅 (使用 Smart UA)
    const validRes = await fetchWithSmartUA(url);
    
    if (!validRes || !validRes.ok) return c.json({ success: false, error: `连接失败: ${validRes?validRes.status:0}` })

    // 如果 fetchWithSmartUA 已经提取到了流量信息，直接用
    if (validRes.trafficInfo) {
        resultData.stats = validRes.trafficInfo;
    } 
    // 否则再尝试解析一次 header (双重保险)
    else {
        const info = extractUserInfo(validRes.headers);
        if (info) resultData.stats = info;
    }

    const text = await validRes.text()
    const nodeList = parseNodesCommon(text)
    
    // 如果流量正常但节点为0，强制 Base64 解码重试 (应对 text/plain 响应头导致的误判)
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
app.get('/settings', async(c)=>{return c.json({success:true,data:{}})}) // 简化
app.post('/settings', async(c)=>{return c.json({success:true})}) // 简化
app.get('/template/default', async (c) => { const {results}=await c.env.DB.prepare("SELECT content FROM templates WHERE is_default=1").all(); return c.json({success:true, data: results[0]?.content||""}) })
app.post('/template/default', async (c) => { const {content}=await c.req.json(); await c.env.DB.prepare("UPDATE templates SET content=? WHERE is_default=1").bind(content).run(); return c.json({success:true}) })
app.post('/login', async (c) => { const {password}=await c.req.json(); return (password===c.env.ADMIN_PASSWORD)?c.json({success:true}):c.json({success:false},401) })

export const onRequest = handle(app)
