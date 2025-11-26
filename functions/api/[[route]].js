import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono().basePath('/api')
app.use('/*', cors())

// --- 鉴权中间件 ---
app.use('/*', async (c, next) => {
  const path = c.req.path
  if (path.endsWith('/login') || path.includes('/g/')) return await next()
  const authHeader = c.req.header('Authorization')
  if (authHeader !== c.env.ADMIN_PASSWORD) return c.json({ success: false, error: 'Unauthorized' }, 401)
  await next()
})
app.onError((err, c) => c.json({ error: err.message }, 500))

// --- 工具函数 ---
const generateToken = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 16; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
    return result;
}

const formatBytes = (bytes) => {
  if (!bytes || isNaN(bytes) || bytes === 0) return '0 B'
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

const safeBase64Decode = (str) => {
    if (!str) return '';
    try {
        let clean = str.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
        while (clean.length % 4) clean += '=';
        return decodeURIComponent(escape(atob(clean)));
    } catch (e) { return str; }
}
const safeBase64Encode = (str) => { try { return btoa(unescape(encodeURIComponent(str))); } catch (e) { return btoa(str); } }
const deepBase64Decode = (str, depth = 0) => {
    if (depth > 3) return str;
    if (!str || typeof str !== 'string') return str;
    try {
        const clean = str.replace(/\s/g, '');
        if (!/^[A-Za-z0-9+/=_:-]+$/.test(clean) || clean.length < 10) return str;
        if (clean.includes('proxies:') || clean.includes('mixed-port:') || clean.includes('proxy-groups:')) return str;
        let safeStr = clean.replace(/-/g, '+').replace(/_/g, '/');
        while (safeStr.length % 4) safeStr += '=';
        const decoded = new TextDecoder('utf-8').decode(Uint8Array.from(atob(safeStr), c => c.charCodeAt(0)));
        if (decoded.includes('://') || decoded.includes('proxies:') || decoded.includes('server:')) return deepBase64Decode(decoded, depth + 1);
        return decoded;
    } catch (e) { return str; }
}

// --- 核心：智能 Fetch (含流量解析) ---
const extractUserInfo = (headers) => {
    let infoStr = null;
    headers.forEach((val, key) => { if (key.toLowerCase().includes('userinfo')) infoStr = val; });
    if (!infoStr) return null;
    const info = {};
    infoStr.split(';').forEach(part => { const [key, value] = part.trim().split('='); if (key && value) info[key.trim().toLowerCase()] = Number(value); });
    if (!info.total && !info.upload && !info.download) return null;
    return {
        used: formatBytes((info.upload || 0) + (info.download || 0)),
        total: info.total ? formatBytes(info.total) : '无限制',
        expire: info.expire ? new Date(info.expire * 1000).toLocaleDateString() : '长期',
        percent: info.total ? Math.min(100, Math.round(((info.upload || 0) + (info.download || 0)) / info.total * 100)) : 0,
        raw_total: info.total, raw_used: (info.upload || 0) + (info.download || 0), raw_expire: info.expire
    };
}

const fetchWithSmartUA = async (url) => {
  const userAgents = ['ClashMeta/1.0', 'v2rayNG/1.8.5', 'Clash/1.0', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'];
  let bestRes = null;
  for (const ua of userAgents) {
    try {
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), 10000);
      const res = await fetch(url, { 
          headers: { 'User-Agent': ua }, 
          signal: controller.signal,
          cache: 'no-store' 
      });
      clearTimeout(id);
      if (res.ok) {
        const clone = res.clone();
        const text = await clone.text();
        if (text.includes('<!DOCTYPE html>') || text.includes('<html')) continue;
        
        // 提取流量信息
        const info = extractUserInfo(res.headers);
        if (info) {
            // 将流量信息挂载到 response 对象上返回，以便后续处理
            Object.defineProperty(res, 'trafficInfo', { value: info, writable: true });
        }
        Object.defineProperty(res, 'prefetchedText', { value: text, writable: true });
        return res;
      }
    } catch (e) {}
  }
  return bestRes;
}

// --- 核心：生成链接 (透传优先) ---
const generateNodeLink = (node) => {
    try {
        const safe = (s) => encodeURIComponent(s || '');
        // 1. VMess 必须重组 (Base64 JSON)
        if (node.type === 'vmess') {
            const vmessObj = {
                v: "2", ps: node.name, add: node.server, port: node.port, id: node.uuid,
                aid: 0, scy: node.cipher||"auto", net: node.network || "tcp", type: "none", host: "", path: "", tls: node.tls ? "tls" : ""
            };
            if (node["ws-opts"]) {
                vmessObj.net = "ws";
                vmessObj.path = node["ws-opts"].path;
                if (node["ws-opts"].headers) vmessObj.host = node["ws-opts"].headers.Host;
            }
            if (node.flow) vmessObj.flow = node.flow;
            return 'vmess://' + safeBase64Encode(JSON.stringify(vmessObj));
        }
        // 2. 其他协议透传，仅修改 Hash
        if (node.origLink) {
            try {
                const u = new URL(node.origLink);
                u.hash = safe(node.name);
                return u.toString();
            } catch(e) {
                const hashIndex = node.origLink.lastIndexOf('#');
                if (hashIndex !== -1) return node.origLink.substring(0, hashIndex) + '#' + safe(node.name);
                return node.origLink + '#' + safe(node.name);
            }
        }
        return node.link || '';
    } catch (e) { return ''; }
}

// --- 核心：解析器 ---
const parseNodesCommon = (text) => {
    let nodes = [];
    let decoded = deepBase64Decode(text);
    
    // 简单判断是否是 YAML (虽然我们删除了 Clash 生成，但解析还是要兼容)
    if (decoded.includes('proxies:') || decoded.includes('Proxy:') || decoded.includes('- name:')) {
        const lines = decoded.split(/\r?\n/);
        let inProxyBlock = false;
        const parseLineObj = (line) => {
            const getVal = (k) => { const reg = new RegExp(`${k}:\\s*(?:['"](.*?)['"]|(.*?))(?:$|,|\\}|\\n)`, 'i'); const m = line.match(reg); return m ? (m[1] || m[2]).trim() : undefined; };
            let type = getVal('type'), server = getVal('server'), port = getVal('port'), name = getVal('name');
            if (!type && line.includes('ss')) type = 'ss'; if (!type && line.includes('vmess')) type = 'vmess';
            if (type && server && port) {
                 const node = { name: name || `${type}-${server}`, type, server, port, cipher: getVal('cipher'), uuid: getVal('uuid'), password: getVal('password'), tls: line.includes('tls: true') || getVal('tls') === 'true', "skip-cert-verify": line.includes('skip-cert-verify: true'), servername: getVal('servername') || getVal('sni'), sni: getVal('sni'), network: getVal('network'), "ws-opts": undefined };
                if (node.network === 'ws') { node["ws-opts"] = { path: getVal('path')||'/', headers: { Host: getVal('host')||'' } }; }
                node.link = generateNodeLink(node); nodes.push(node);
            }
        }
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim(); if (!line) continue;
            if (/^(proxies|Proxy):/i.test(line)) { inProxyBlock = true; continue; }
            if (/^(proxy-groups|rules|rule-providers):/i.test(line)) { inProxyBlock = false; break; }
            if (inProxyBlock && line.startsWith('-')) { if (line.includes('name:') && line.includes('server:')) { parseLineObj(line); } else { let temp = line; let j = 1; while (i + j < lines.length && !lines[i+j].trim().startsWith('-')) { temp += " " + lines[i+j].trim(); j++; } parseLineObj(temp); } }
        }
        if (nodes.length > 0) return nodes;
    }

    // 通用链接处理
    const splitText = decoded.replace(/(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//gi, '\n$1://');
    const lines = splitText.split(/[\r\n]+/);
    for (const line of lines) {
        const trimLine = line.trim(); 
        if (!trimLine || trimLine.length < 10) continue;
        try {
            if (trimLine.startsWith('vmess://')) {
                const c = JSON.parse(safeBase64Decode(trimLine.substring(8)));
                nodes.push({ name: c.ps, type: 'vmess', server: c.add, port: c.port, uuid: c.id, cipher: c.scy||'auto', network: c.net, tls: c.tls==='tls', "ws-opts": c.net==='ws' ? { path: c.path, headers: { Host: c.host } } : undefined, flow: c.flow, link: trimLine, origLink: trimLine });
                continue;
            }
            if (/^(vless|ss|trojan|hysteria2?|tuic):\/\//i.test(trimLine)) {
                const url = new URL(trimLine); const params = url.searchParams; const protocol = url.protocol.replace(':', '');
                let node = { name: decodeURIComponent(url.hash.substring(1)), type: protocol === 'hysteria' ? 'hysteria2' : protocol, server: url.hostname, port: parseInt(url.port), uuid: url.username, password: url.password || url.username, tls: params.get('security') === 'tls' || protocol === 'hysteria2' || protocol === 'tuic', network: params.get('type') || 'tcp', sni: params.get('sni'), servername: params.get('sni') || params.get('host'), "skip-cert-verify": params.get('allowInsecure') === '1' || params.get('insecure') === '1', flow: params.get('flow'), "client-fingerprint": params.get('fp'), origLink: trimLine };
                if (protocol === 'ss') { let userStr = url.username; try { userStr = decodeURIComponent(url.username); } catch(e) {} if (userStr.includes(':')) { const parts = userStr.split(':'); node.cipher = parts[0]; node.password = parts.slice(1).join(':'); } else { try { const decoded = safeBase64Decode(url.username); if (decoded && decoded.includes(':')) { const parts = decoded.split(':'); node.cipher = parts[0]; node.password = parts.slice(1).join(':'); } } catch(e) {} } if (!node.cipher && url.password) { node.cipher = decodeURIComponent(url.username); node.password = decodeURIComponent(url.password); } }
                if (node.network === 'ws') node['ws-opts'] = { path: params.get('path')||'/', headers: { Host: params.get('host')||node.servername } };
                if (params.get('security') === 'reality') { node.tls = true; node.reality = { publicKey: params.get('pbk'), shortId: params.get('sid') }; if(!node['client-fingerprint']) node['client-fingerprint']='chrome'; }
                if (protocol === 'hysteria2') { node.obfs = params.get('obfs'); node['obfs-password'] = params.get('obfs-password'); node.udp = true; }
                if (protocol === 'tuic') { node['congestion-controller'] = params.get('congestion_control'); node['udp-relay-mode'] = params.get('udp_relay_mode'); node.alpn = [params.get('alpn')||'h3']; node.udp = true; }
                if ((protocol === 'vless' || protocol === 'trojan') && node.network === 'ws') node.udp = true;
                nodes.push(node);
            }
        } catch(e) {}
    }
    return nodes.map(n => { if (!n.link) n.link = generateNodeLink(n); return n; });
}

// --- 核心路由：聚合组订阅入口 (无需密码) ---
app.get('/g/:token', async (c) => {
    const token = c.req.param('token');
    const format = c.req.query('format') || 'base64'; // clash or base64
    
    try {
        // 1. 查找聚合组
        const group = await c.env.DB.prepare("SELECT * FROM groups WHERE token = ? AND status = 1").bind(token).first();
        if (!group) return c.text('Invalid Group Token', 404);

        const config = JSON.parse(group.config || '[]'); // 结构: [{ subId: 1, include: 'all' OR ['Node A'] }]
        
        // 2. 遍历配置，获取节点
        let allNodes = [];
        for (const item of config) {
            const sub = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE id = ?").bind(item.subId).first();
            if (!sub) continue; // 如果订阅不存在，跳过

            let content = "";
            if (sub.type === 'node') {
                content = sub.url;
            } else {
                // 强制从网络拉取，不使用缓存，确保获取最新节点
                const res = await fetchWithSmartUA(sub.url);
                if (res && res.ok) content = res.prefetchedText || await res.text();
            }
            
            if (!content) continue; // 如果内容为空，跳过

            const nodes = parseNodesCommon(content);
            // 解析配置中的筛选规则
            let allowed = 'all';
            if (item.include && Array.isArray(item.include) && item.include.length > 0) {
                allowed = new Set(item.include);
            }

            for (const node of nodes) {
                // 筛选逻辑
                if (allowed !== 'all' && !allowed.has(node.name)) continue;

                // 重名处理 (简单追加序号)
                let name = node.name.trim();
                let i = 1;
                while (allNodes.some(n => n.name === name)) name = `${node.name} ${i++}`;
                node.name = name;
                
                allNodes.push(node);
            }
        }

        // 3. 输出结果
        if (format === 'clash') {
            // 暂时移除 Clash 生成逻辑，返回占位符
            return c.text("# Clash support is temporarily disabled in this version.\n# Please use V2Ray/Base64 subscription.", 200, { 
                'Content-Type': 'text/plain; charset=utf-8', 
                'Cache-Control': 'no-store' 
            });
        } else {
            // Base64 (V2RayN) - 严格透传
            const links = allNodes.map(node => generateNodeLink(node));
            return c.text(btoa(encodeURIComponent(links.join('\n')).replace(/%([0-9A-F]{2})/g, (m, p1) => String.fromCharCode('0x' + p1))), 200, { 
                'Content-Type': 'text/plain; charset=utf-8', 
                'Cache-Control': 'no-store' 
            });
        }

    } catch(e) { return c.text(e.message, 500); }
})

// --- 资源池管理 (Subscriptions) ---
app.get('/subs', async (c) => { 
    const {results} = await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY sort_order ASC, id DESC").all(); 
    // 解析 info 字段，确保前端能读到流量信息
    return c.json({success:true, data:results.map(i=>{
        try { i.info = JSON.parse(i.info); } catch(e) { i.info = {}; }
        return i;
    })}) 
})
app.post('/subs', async (c) => { const b=await c.req.json(); await c.env.DB.prepare("INSERT INTO subscriptions (name,url,type,params,info,sort_order,status) VALUES (?,?,?,?,?,0,1)").bind(b.name,b.url,b.type||'sub',JSON.stringify({}),'{}').run(); return c.json({success:true}) })
app.put('/subs/:id', async (c) => { 
    const b = await c.req.json(); const id = c.req.param('id');
    let parts = ["updated_at=CURRENT_TIMESTAMP"]; let args = [];
    if (b.name!==undefined){parts.push("name=?");args.push(b.name)} if(b.url!==undefined){parts.push("url=?");args.push(b.url)}
    if (b.type!==undefined){parts.push("type=?");args.push(b.type)} if(b.status!==undefined){parts.push("status=?");args.push(parseInt(b.status))}
    if (b.info){parts.push("info=?");args.push(JSON.stringify(b.info))}
    const query = `UPDATE subscriptions SET ${parts.join(', ')} WHERE id=?`; args.push(id);
    await c.env.DB.prepare(query).bind(...args).run(); return c.json({success:true}) 
})
app.delete('/subs/:id', async (c) => { await c.env.DB.prepare("DELETE FROM subscriptions WHERE id=?").bind(c.req.param('id')).run(); return c.json({success:true}) })
app.post('/sort', async (c) => { const {ids}=await c.req.json(); const s=c.env.DB.prepare("UPDATE subscriptions SET sort_order=? WHERE id=?"); await c.env.DB.batch(ids.map((id,i)=>s.bind(i,id))); return c.json({success:true}) })

// --- 聚合组管理 (Groups) ---
app.get('/groups', async (c) => { const {results} = await c.env.DB.prepare("SELECT * FROM groups ORDER BY sort_order ASC, id DESC").all(); return c.json({success:true, data:results.map(g => ({...g, config: JSON.parse(g.config||'[]')}))}) })
app.post('/groups', async (c) => { 
    const b=await c.req.json(); 
    const token = generateToken();
    await c.env.DB.prepare("INSERT INTO groups (name, token, config, status, sort_order) VALUES (?, ?, ?, 1, 0)").bind(b.name, token, JSON.stringify(b.config||[])).run(); 
    return c.json({success:true}) 
})
app.put('/groups/:id', async (c) => {
    const b = await c.req.json(); const id = c.req.param('id');
    let parts = ["updated_at=CURRENT_TIMESTAMP"]; let args = [];
    if(b.name!==undefined){parts.push("name=?");args.push(b.name)} 
    if(b.config!==undefined){parts.push("config=?");args.push(JSON.stringify(b.config))}
    if(b.status!==undefined){parts.push("status=?");args.push(parseInt(b.status))}
    if(b.refresh_token){parts.push("token=?");args.push(generateToken())}
    
    const query = `UPDATE groups SET ${parts.join(', ')} WHERE id=?`; args.push(id);
    await c.env.DB.prepare(query).bind(...args).run(); return c.json({success:true})
})
app.delete('/groups/:id', async (c) => { await c.env.DB.prepare("DELETE FROM groups WHERE id=?").bind(c.req.param('id')).run(); return c.json({success:true}) })

// --- 公共接口 ---
app.post('/check', async (c) => {
    const { url, type } = await c.req.json();
    try {
        let content = ""; let stats = null;
        if (type === 'node') { content = url; } 
        else {
            const res = await fetchWithSmartUA(url);
            if(!res || !res.ok) throw new Error(`Connect Failed`);
            content = res.prefetchedText || await res.text();
            if(res.trafficInfo) stats = res.trafficInfo;
        }
        const rawNodes = parseNodesCommon(content);
        const nodes = rawNodes.map(n => ({ ...n, link: generateNodeLink(n) }));
        return c.json({ success: true, data: { valid: true, nodeCount: nodes.length, stats, nodes } });
    } catch(e) { return c.json({ success: false, error: e.message }) }
})

app.post('/login', async (c) => { const {password}=await c.req.json(); return c.json({success: password===c.env.ADMIN_PASSWORD}) })
app.get('/template/default', async (c) => { const {results}=await c.env.DB.prepare("SELECT content FROM templates WHERE is_default=1").all(); return c.json({success:true, data: results[0]?.content||""}) })
app.post('/template/default', async (c) => { const {content}=await c.req.json(); await c.env.DB.prepare("UPDATE templates SET content=? WHERE is_default=1").bind(content).run(); return c.json({success:true}) })
app.get('/settings', async(c)=>{return c.json({success:true,data:{}})}) 
app.post('/settings', async(c)=>{return c.json({success:true})})
app.post('/backup/import', async (c) => { 
    const {items, groups}=await c.req.json(); 
    if(items) { const s=c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, params, status, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)"); await c.env.DB.batch(items.map(i=>s.bind(i.name,i.url,i.type||'subscription',JSON.stringify(i.info),JSON.stringify({}),i.status??1,i.sort_order??0))); }
    if(groups) { const s=c.env.DB.prepare("INSERT INTO groups (name, token, config, status, sort_order) VALUES (?, ?, ?, ?, ?)"); await c.env.DB.batch(groups.map(g=>s.bind(g.name, g.token, JSON.stringify(g.config), g.status??1, g.sort_order??0))); }
    return c.json({success:true}) 
})

export const onRequest = handle(app)
