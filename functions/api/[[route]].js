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
        // 简单放宽检查，防止误杀
        if (clean.length < 10) return str;
        // 如果包含明文特征，直接返回，不再解码
        if (clean.includes('proxies:') || clean.includes('mixed-port:') || clean.includes('ss://') || clean.includes('vmess://')) return str;
        
        let safeStr = clean.replace(/-/g, '+').replace(/_/g, '/');
        while (safeStr.length % 4) safeStr += '=';
        const decoded = new TextDecoder('utf-8').decode(Uint8Array.from(atob(safeStr), c => c.charCodeAt(0)));
        
        // 如果解码后看起来还是 Base64 或者包含 URL 编码，递归
        if (decoded.includes('://') || decoded.includes('proxies:') || decoded.includes('server:')) {
            return deepBase64Decode(decoded, depth + 1); // 可能是多重 Base64
        }
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
      const id = setTimeout(() => controller.abort(), 15000); // 延长一点超时
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
        
        const info = extractUserInfo(res.headers);
        if (info) Object.defineProperty(res, 'trafficInfo', { value: info, writable: true });
        Object.defineProperty(res, 'prefetchedText', { value: text, writable: true });
        return res;
      }
    } catch (e) {}
  }
  return bestRes;
}

// --- 核心：生成链接 (强力透传模式) ---
const generateNodeLink = (node) => {
    // 优先 1: 如果有原始链接，尽最大努力只修改名称(PS/Hash)并返回原始链接
    if (node.origLink) {
        try {
            const safeName = encodeURIComponent(node.name || '');
            
            // VMess: 必须解码 JSON 修改 ps 字段
            if (node.origLink.startsWith('vmess://')) {
                const base64Part = node.origLink.substring(8);
                try {
                    const jsonStr = safeBase64Decode(base64Part);
                    const vmessObj = JSON.parse(jsonStr);
                    vmessObj.ps = node.name;
                    return 'vmess://' + safeBase64Encode(JSON.stringify(vmessObj));
                } catch(e) {
                    // 如果解析失败，直接返回原始链接，放弃改名
                    return node.origLink;
                }
            }
            
            // 其他 URL 类型 (ss, vless, trojan, hysteria...): 修改 Hash 部分
            // 尝试构建 URL 对象
            try {
                const u = new URL(node.origLink);
                u.hash = safeName;
                return u.toString();
            } catch(e) {
                // 如果 URL 对象解析失败，进行字符串替换
                const hashIndex = node.origLink.lastIndexOf('#');
                if (hashIndex !== -1) {
                    return node.origLink.substring(0, hashIndex) + '#' + safeName;
                } else {
                    return node.origLink + '#' + safeName;
                }
            }
        } catch (e) {
            // 万一所有修改尝试都失败，返回原始链接，保底
            return node.origLink;
        }
    }

    // 优先 2: 如果没有原始链接 (比如来自 YAML 解析)，尝试根据字段构建
    try {
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
        // 这里可以补充 SS 等其他协议的构建逻辑，但目前的解析器主要依赖原始链接
        // 对于 YAML 导入的非 VMess 节点，目前仅支持基础属性，如有需要可继续扩展
        return ''; 
    } catch (e) { return ''; }
}

// --- 核心：解析器 (增强版) ---
const parseNodesCommon = (text) => {
    let nodes = [];
    // 尝试解码，如果不是 Base64 则保持原样
    let decoded = deepBase64Decode(text);
    if (!decoded) return [];

    // 1. 尝试 YAML 解析 (兼容 Clash 格式)
    if (decoded.includes('proxies:') || decoded.includes('Proxy:') || /^\s*-\s*name:/m.test(decoded)) {
        const lines = decoded.split(/\r?\n/);
        let inProxyBlock = false;
        
        const parseLineObj = (lineStr) => {
            // 增强的正则提取，兼容更多格式
            const getVal = (k) => { 
                const reg = new RegExp(`${k}:\\s*(?:['"](.*?)['"]|(.*?))(?:$|,|\\}|\\n)`, 'i'); 
                const m = lineStr.match(reg); 
                return m ? (m[1] || m[2]).trim() : undefined; 
            };

            let type = getVal('type'), server = getVal('server'), port = getVal('port'), name = getVal('name');
            
            // 修正部分常见缩写或缺失
            if (!type && lineStr.includes('ss')) type = 'ss'; 
            if (!type && lineStr.includes('vmess')) type = 'vmess';

            if (type && server && port) {
                 const node = { 
                     name: name || `${type}-${server}`, 
                     type, server, port, 
                     cipher: getVal('cipher'), 
                     uuid: getVal('uuid'), 
                     password: getVal('password'), 
                     tls: lineStr.includes('tls: true') || getVal('tls') === 'true', 
                     "skip-cert-verify": lineStr.includes('skip-cert-verify: true'), 
                     servername: getVal('servername') || getVal('sni'), 
                     sni: getVal('sni'), 
                     network: getVal('network'), 
                     "ws-opts": undefined 
                };
                
                // WS 提取
                if (node.network === 'ws' || lineStr.includes('network: ws')) {
                    node.network = 'ws';
                    const path = getVal('path');
                    const host = getVal('host') || getVal('headers.*?Host'); // 简单尝试提取 Host
                    node["ws-opts"] = { path: path||'/', headers: { Host: host||'' } }; 
                }
                
                // YAML 解析出来的没有 origLink，必须完全依赖构建
                node.link = generateNodeLink(node); 
                nodes.push(node);
            }
        }

        // 遍历行处理
        let buffer = ""; 
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            
            // 简单状态机
            if (/^(proxies|Proxy):/i.test(line)) { inProxyBlock = true; continue; }
            if (/^(proxy-groups|rules|rule-providers):/i.test(line)) { inProxyBlock = false; break; }
            
            if (inProxyBlock) {
                if (line.startsWith('-')) {
                    // 处理上一条 buffer
                    if (buffer) parseLineObj(buffer);
                    buffer = line;
                } else {
                    // 追加到当前 buffer (处理多行定义)
                    buffer += " " + line;
                }
            }
        }
        if (buffer) parseLineObj(buffer); // 处理最后一条
        
        if (nodes.length > 0) return nodes;
    }

    // 2. 通用链接处理 (Base64 解码后的文本行)
    // 强制给协议头加上换行，防止挤在一行
    const splitText = decoded.replace(/(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//gi, '\n$1://');
    const lines = splitText.split(/[\r\n]+/);
    
    for (const line of lines) {
        const trimLine = line.trim(); 
        if (!trimLine || trimLine.length < 10) continue;
        
        // 必须是已知协议开头
        if (!/^(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//i.test(trimLine)) continue;

        try {
            // VMess 特殊处理
            if (trimLine.startsWith('vmess://')) {
                const b64 = trimLine.substring(8);
                const c = JSON.parse(safeBase64Decode(b64));
                nodes.push({ 
                    name: c.ps, type: 'vmess', server: c.add, port: c.port, 
                    uuid: c.id, cipher: c.scy||'auto', network: c.net, 
                    tls: c.tls==='tls', 
                    "ws-opts": c.net==='ws' ? { path: c.path, headers: { Host: c.host } } : undefined, 
                    flow: c.flow, 
                    link: trimLine, // 这里的 link 暂时存着
                    origLink: trimLine // 关键：保存原始链接
                });
                continue;
            }

            // URL 类协议解析
            const url = new URL(trimLine); 
            const params = url.searchParams; 
            const protocol = url.protocol.replace(':', '');
            
            // 基础信息提取，主要是为了前端展示 valid check，核心还是靠 origLink
            let node = { 
                name: decodeURIComponent(url.hash.substring(1)), 
                type: protocol === 'hysteria' ? 'hysteria2' : protocol, 
                server: url.hostname, 
                port: parseInt(url.port),
                origLink: trimLine 
            };
            
            // 仅做简单填充，为了 generateNodeLink 的 fallback，主要依赖 origLink
            nodes.push(node);
        } catch(e) {
            // 解析失败时，如果看起来像个链接，也强行加入，保留原始链接
            if (trimLine.includes('://')) {
                nodes.push({ name: 'Unknown Node', type: 'raw', origLink: trimLine });
            }
        }
    }
    
    // 最后统一生成/修正 link 字段
    return nodes.map(n => { 
        n.link = generateNodeLink(n); 
        // 如果名字是空的，尝试从 link 里截取或者默认
        if (!n.name && n.link) {
            try {
               if(n.link.startsWith('vmess://')) {
                   const c = JSON.parse(safeBase64Decode(n.link.substring(8)));
                   n.name = c.ps;
               } else {
                   const u = new URL(n.link);
                   n.name = decodeURIComponent(u.hash.substring(1));
               }
            } catch(e){}
        }
        if (!n.name) n.name = "Node";
        return n; 
    }).filter(n => n.link && n.link.length > 0); // 过滤掉无效节点
}

// --- 核心路由：聚合组订阅入口 ---
app.get('/g/:token', async (c) => {
    const token = c.req.param('token');
    
    try {
        // 1. 查找聚合组
        const group = await c.env.DB.prepare("SELECT * FROM groups WHERE token = ? AND status = 1").bind(token).first();
        if (!group) return c.text('Invalid Group Token', 404);

        const config = JSON.parse(group.config || '[]'); 
        
        // 2. 遍历配置，获取节点
        let allNodes = [];
        for (const item of config) {
            const sub = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE id = ?").bind(item.subId).first();
            if (!sub) continue; 

            let content = "";
            if (sub.type === 'node') {
                content = sub.url;
            } else {
                const res = await fetchWithSmartUA(sub.url);
                if (res && res.ok) content = res.prefetchedText || await res.text();
            }
            
            if (!content) continue;

            const nodes = parseNodesCommon(content);
            
            let allowed = 'all';
            if (item.include && Array.isArray(item.include) && item.include.length > 0) {
                allowed = new Set(item.include);
            }

            for (const node of nodes) {
                if (allowed !== 'all' && !allowed.has(node.name)) continue;

                // 重名处理
                let name = node.name.trim();
                let i = 1;
                while (allNodes.some(n => n.name === name)) name = `${node.name} ${i++}`;
                
                // 更新节点名称
                node.name = name;
                // 重新生成链接以应用新名称
                node.link = generateNodeLink(node);
                
                allNodes.push(node);
            }
        }

        // 3. 输出结果 (仅 Base64)
        const links = allNodes.map(node => node.link).filter(l => l);
        return c.text(btoa(encodeURIComponent(links.join('\n')).replace(/%([0-9A-F]{2})/g, (m, p1) => String.fromCharCode('0x' + p1))), 200, { 
            'Content-Type': 'text/plain; charset=utf-8', 
            'Cache-Control': 'no-store' 
        });

    } catch(e) { return c.text(e.message, 500); }
})

// --- 资源池管理 (Subscriptions) ---
app.get('/subs', async (c) => { 
    const {results} = await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY sort_order ASC, id DESC").all(); 
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
        const nodes = parseNodesCommon(content);
        return c.json({ success: true, data: { valid: true, nodeCount: nodes.length, stats, nodes } });
    } catch(e) { return c.json({ success: false, error: e.message }) }
})

app.post('/login', async (c) => { const {password}=await c.req.json(); return c.json({success: password===c.env.ADMIN_PASSWORD}) })
app.get('/settings', async(c)=>{return c.json({success:true,data:{}})}) 
app.post('/settings', async(c)=>{return c.json({success:true})})
app.post('/backup/import', async (c) => { 
    const {items, groups}=await c.req.json(); 
    if(items) { const s=c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, params, status, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)"); await c.env.DB.batch(items.map(i=>s.bind(i.name,i.url,i.type||'subscription',JSON.stringify(i.info),JSON.stringify({}),i.status??1,i.sort_order??0))); }
    if(groups) { const s=c.env.DB.prepare("INSERT INTO groups (name, token, config, status, sort_order) VALUES (?, ?, ?, ?, ?)"); await c.env.DB.batch(groups.map(g=>s.bind(g.name, g.token, JSON.stringify(g.config), g.status??1, g.sort_order??0))); }
    return c.json({success:true}) 
})

export const onRequest = handle(app)
