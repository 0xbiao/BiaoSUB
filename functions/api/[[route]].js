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
    // 排除内网和无效域名
    if (!host || host.match(/^(127\.|192\.168\.|10\.|localhost)/)) return null;
    const res = await fetch(`http://ip-api.com/json/${host}?fields=status,country,countryCode,query`)
    const data = await res.json()
    if (data.status === 'success') {
      return { country: data.country, code: data.countryCode, ip: data.query }
    }
  } catch (e) {}
  return null
}

// 智能 Fetch：升级版 User-Agent 库
const fetchWithSmartUA = async (url) => {
  const userAgents = [
    'Clash.Meta/1.16.0',          // 新版 Clash 核心
    'ClashVerge/1.3.8',           // Clash Verge
    'Clash/1.0',                  // 经典兼容标识
    'v2rayNG/1.8.19',             // 安卓主流
    'Stash/2.4.5',                // iOS 主流
    'Quantumult%20X/1.0.30',      // 圈X
    'Mozilla/5.0'                 // 浏览器兜底
  ];

  let lastRes = null;

  for (const ua of userAgents) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // 15秒超时
      
      const res = await fetch(url, { 
          headers: { 
              'User-Agent': ua,
              'Accept': '*/*'
          }, 
          signal: controller.signal 
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        lastRes = res;
        // 只要拿到流量信息，就认为这个 UA 是对的，停止轮询
        const info = extractUserInfo(res.headers);
        if (info) {
            // 将流量信息挂载到响应对象上
            Object.defineProperty(res, 'trafficInfo', { value: info, writable: true });
            return res; 
        }
        // 如果拿到了内容且包含节点特征，也算成功
        const clone = res.clone();
        const text = await clone.text();
        if (text.includes('proxies:') || text.includes('vmess://') || text.includes('ss://')) {
             // 恢复 body 供后续使用
             return res;
        }
      }
    } catch (e) {}
  }
  return lastRes;
}

const extractUserInfo = (headers) => {
    let infoStr = null;
    // 遍历 Header，忽略大小写差异
    headers.forEach((val, key) => {
        if (key.toLowerCase().includes('userinfo')) infoStr = val;
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
    // 移除所有非 Base64 字符
    let clean = str.replace(/[^A-Za-z0-9+/=]/g, '');
    // 补全 padding
    while (clean.length % 4) clean += '=';
    
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder('utf-8').decode(bytes);
  } catch (e) { return null }
}

const safeStr = (str) => {
    if (!str) return '""';
    const s = String(str).trim();
    if (/[:#\[\]\{\},&*!|>'%@]/.test(s) || /^\s|\s$/.test(s)) return JSON.stringify(s);
    return s;
}

// --- 3. 核心：暴力节点解析器 ---

// 暴力 YAML 解析：不依赖标准缩进，只抓取 proxies 块里的列表项
const parseYamlProxies = (content) => {
    const nodes = [];
    try {
        // 1. 截取 proxies 区域
        const proxyMatch = content.match(/^(?:proxies|Proxy):\s*\n([\s\S]*?)(?:^(?:proxy-groups|rules|rule-providers):|\z)/m);
        if (!proxyMatch) return nodes;
        
        const blockContent = proxyMatch[1];
        
        // 2. 使用正则分割列表项 (匹配行首的 - )
        const items = blockContent.split(/^[\t ]*-\s+/m);
        
        for (const item of items) {
            if (!item.trim()) continue; // 跳过空项
            
            // 提取字段函数
            const getVal = (key) => {
                const reg = new RegExp(`^\\s*${key}:\\s*(?:['"](.*?)['"]|(.*?))\\s*(?:$|#)`, 'm');
                const m = item.match(reg);
                return m ? (m[1] || m[2]).trim() : undefined;
            };

            const type = getVal('type');
            if (!type || !['vmess', 'vless', 'trojan', 'ss', 'hysteria2', 'tuic'].includes(type)) continue;

            const server = getVal('server');
            const port = getVal('port');
            if (!server || !port) continue;

            const node = {
                name: getVal('name') || `${type}-${server}`,
                type, server, port,
                cipher: getVal('cipher'),
                uuid: getVal('uuid'),
                password: getVal('password'),
                tls: getVal('tls') === 'true',
                "skip-cert-verify": getVal('skip-cert-verify') === 'true',
                servername: getVal('servername') || getVal('sni'),
                network: getVal('network'),
                "ws-opts": undefined
            };

            // 提取 ws-opts (简易版)
            if (node.network === 'ws') {
                const path = getVal('path');
                const hostMatch = item.match(/headers:[\s\S]*?Host:\s*(.*?)(?:\n|$)/i);
                node["ws-opts"] = {
                    path: path || '/',
                    headers: { Host: hostMatch ? hostMatch[1].trim().replace(/['"]/g, '') : '' }
                };
            }
            // 生成模拟链接供前端使用
            node.link = `${type}://${node.server}:${node.port}#${encodeURIComponent(node.name)}`;
            nodes.push(node);
        }
    } catch(e) { console.error(e) }
    return nodes;
}

// 主解析入口：多轮尝试
const parseNodesCommon = (text) => {
    if (!text) return [];
    let nodes = [];

    // 策略1：直接尝试 YAML 解析
    if (text.includes('proxies:') || text.includes('Proxy:')) {
        nodes = parseYamlProxies(text);
        if (nodes.length > 0) return nodes;
    }

    // 策略2：尝试 Base64 解码后再解析
    let decodedText = text;
    // 只有当内容不包含明显链接特征时才尝试解码
    if (!text.includes('://')) {
        const decoded = safeBase64Decode(text);
        if (decoded) {
            decodedText = decoded;
            // 解码后再次尝试 YAML (套娃情况)
            if (decodedText.includes('proxies:') || decodedText.includes('Proxy:')) {
                nodes = parseYamlProxies(decodedText);
                if (nodes.length > 0) return nodes;
            }
        }
    }

    // 策略3：行级正则解析 (VMess/SS/VLESS/Hy2)
    const lines = decodedText.split(/\r?\n/);
    const regex = /^(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//i;

    for (const line of lines) {
        const trimLine = line.trim();
        if (!trimLine) continue;

        if (trimLine.startsWith('vmess://')) {
            try {
                const jsonStr = safeBase64Decode(trimLine.substring(8));
                const conf = JSON.parse(jsonStr);
                nodes.push({
                    name: conf.ps || 'vmess', type: 'vmess', link: trimLine,
                    server: conf.add, port: conf.port, uuid: conf.id, alterId: conf.aid||0, 
                    cipher: "auto", tls: conf.tls==="tls", servername: conf.host||"", 
                    network: conf.net||"tcp", "ws-opts": conf.net==="ws" ? { path: conf.path||"/", headers: { Host: conf.host||"" } } : undefined
                });
            } catch (e) {}
            continue;
        }

        if (trimLine.match(regex)) {
            const protocol = trimLine.split(':')[0].toLowerCase();
            let name = `${protocol}节点`;
            const hashIndex = trimLine.lastIndexOf('#');
            if (hashIndex !== -1) {
                try { name = decodeURIComponent(trimLine.substring(hashIndex + 1)) } catch (e) { name = trimLine.substring(hashIndex + 1) }
            }
            let details = {};
            try {
                const urlObj = new URL(trimLine);
                const params = urlObj.searchParams;
                details = {
                    server: urlObj.hostname, port: urlObj.port, uuid: urlObj.username, password: urlObj.username || urlObj.password,
                    sni: params.get("sni")||"", servername: params.get("sni")||"", "skip-cert-verify": true,
                    network: params.get("type")||"tcp", tls: params.get("security")==="tls",
                    cipher: protocol === 'ss' ? urlObj.username : "auto",
                    "ws-opts": params.get("type")==="ws" ? { path: params.get("path")||"/", headers: { Host: params.get("host")||"" } } : undefined
                };
                if (protocol === 'ss' && !trimLine.includes('@')) {
                     details.cipher = "aes-256-gcm"; details.password = "dummy";
                }
            } catch(e) {}
            nodes.push({ name, type: protocol, link: trimLine, ...details });
        }
    }
    return nodes;
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
                const res = await fetchWithSmartUA(sub.url)
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

// C. Check 接口 (自动 UA 轮询 + 暴力重试)
app.post('/check', async (c) => {
  try {
    const { url, type, needNodes } = await c.req.json()
    if (!url) return c.json({ success: false, error: '链接为空' })
    let resultData = { valid: false, nodeCount: 0, stats: null, location: null, nodes: [] }

    if (type === 'node') {
      const nodeList = parseNodesCommon(url)
      if (nodeList.length === 0) return c.json({ success: false, error: '未检测到有效节点' })
      resultData.valid = true; resultData.nodeCount = nodeList.length; if (needNodes) resultData.nodes = nodeList
      try { if (nodeList[0].server) resultData.location = await getGeoInfo(nodeList[0].server) } catch(e) {}
      return c.json({ success: true, data: resultData })
    }

    // 使用智能 Fetch 获取内容
    const validRes = await fetchWithSmartUA(url);
    if (!validRes || !validRes.ok) return c.json({ success: false, error: `连接失败: ${validRes?validRes.status:0}` })

    // 1. 优先使用 fetch 过程中已经提取到的流量信息
    if (validRes.trafficInfo) {
        resultData.stats = validRes.trafficInfo;
    } 
    // 2. 再次尝试从 headers 提取 (兜底)
    else {
        const info = extractUserInfo(validRes.headers);
        if (info) resultData.stats = info;
    }

    // 3. 获取文本并解析节点
    const text = await validRes.text()
    let nodeList = parseNodesCommon(text)
    
    // 4. 如果流量读取成功但节点为 0，说明可能是 Base64 没解开，或者格式怪异
    // 尝试强制再次 Base64 解码整个文本
    if (nodeList.length === 0 && resultData.stats) {
         const deepDecoded = safeBase64Decode(text);
         if (deepDecoded) {
             const retryNodes = parseNodesCommon(deepDecoded);
             if (retryNodes.length > 0) nodeList = retryNodes;
         }
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
app.get('/settings', async(c)=>{return c.json({success:true,data:{}})}) 
app.post('/settings', async(c)=>{return c.json({success:true})})
app.get('/template/default', async (c) => { const {results}=await c.env.DB.prepare("SELECT content FROM templates WHERE is_default=1").all(); return c.json({success:true, data: results[0]?.content||""}) })
app.post('/template/default', async (c) => { const {content}=await c.req.json(); await c.env.DB.prepare("UPDATE templates SET content=? WHERE is_default=1").bind(content).run(); return c.json({success:true}) })
app.post('/login', async (c) => { const {password}=await c.req.json(); return (password===c.env.ADMIN_PASSWORD)?c.json({success:true}):c.json({success:false},401) })

export const onRequest = handle(app)
