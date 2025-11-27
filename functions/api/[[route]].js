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

// 极其宽容的 Base64 解码
const safeBase64Decode = (str) => {
    if (!str) return '';
    try {
        let clean = str.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
        while (clean.length % 4) clean += '=';
        const binary = atob(clean);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return new TextDecoder('utf-8').decode(bytes);
    } catch (e) { return str; }
}

const safeBase64Encode = (str) => {
    try {
        const bytes = new TextEncoder().encode(str);
        const binary = String.fromCharCode(...bytes);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    } catch (e) { return btoa(str); }
}

// 递归深度解码：应对多重 Base64 嵌套的情况
const deepBase64Decode = (str, depth = 0) => {
    if (depth > 3) return str;
    if (!str || typeof str !== 'string' || str.length < 10) return str;
    
    // 快速检查：如果包含明显非 Base64 字符（空格除外），直接返回
    // 但 URL safe base64 允许 -_
    if (/[^A-Za-z0-9+/=_ \-\n\r]/.test(str)) return str;

    try {
        let clean = str.replace(/\s/g, '');
        let safeStr = clean.replace(/-/g, '+').replace(/_/g, '/');
        while (safeStr.length % 4) safeStr += '=';
        
        // 尝试解码
        const binary = atob(safeStr);
        // 如果解码出来包含大量不可见字符(二进制)，可能不是文本，放弃
        let nullCount = 0;
        for(let i=0; i<Math.min(binary.length, 100); i++) {
            if(binary.charCodeAt(i) < 8) nullCount++;
        }
        if(nullCount > 2) return str;

        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        const decoded = new TextDecoder('utf-8').decode(bytes);

        // 如果解码后的内容看起来像是 URL 或 代理配置，尝试继续解码（套娃）
        if (decoded.includes('://') || decoded.includes('proxies:') || decoded.includes('vmess://')) {
            return deepBase64Decode(decoded, depth + 1);
        }
        return decoded;
    } catch (e) { return str; }
}

// --- 核心：智能 Fetch (UA 策略调整) ---
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
  // 策略调整：优先使用 v2rayNG 获取 Base64/Raw 列表，因为这最容易解析且不易出错。
  // 只有当 v2rayNG 失败时，才尝试 Clash。
  const userAgents = ['v2rayNG/1.8.5', 'ClashMeta/1.0', 'Mozilla/5.0'];
  
  for (const ua of userAgents) {
    try {
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), 15000);
      const res = await fetch(url, { headers: { 'User-Agent': ua }, signal: controller.signal, cache: 'no-store' });
      clearTimeout(id);
      
      if (res.ok) {
        const clone = res.clone();
        const text = await clone.text();
        
        // 简单验证：必须包含有效内容
        if (text.length < 10) continue; 
        
        const info = extractUserInfo(res.headers);
        if (info) Object.defineProperty(res, 'trafficInfo', { value: info, writable: true });
        Object.defineProperty(res, 'prefetchedText', { value: text, writable: true });
        return res;
      }
    } catch (e) {}
  }
  return null;
}

// --- 核心：生成链接 (标准化) ---
const generateNodeLink = (node) => {
    const safeName = encodeURIComponent(node.name || 'Node');

    // 1. 如果有原始链接，直接复用 (最稳妥)
    if (node.origLink) {
        try {
            // VMess 需要特殊处理改名，因为它的名字藏在 JSON 里
            if (node.origLink.startsWith('vmess://')) {
                const base64Part = node.origLink.substring(8);
                const jsonStr = safeBase64Decode(base64Part);
                const vmessObj = JSON.parse(jsonStr);
                vmessObj.ps = node.name; 
                return 'vmess://' + safeBase64Encode(JSON.stringify(vmessObj));
            }
            // 其他协议直接替换 Hash
            const hashIndex = node.origLink.lastIndexOf('#');
            if (hashIndex !== -1) return node.origLink.substring(0, hashIndex) + '#' + safeName;
            return node.origLink + '#' + safeName;
        } catch(e) {
            return node.origLink; // 解析失败则原样返回
        }
    }

    // 2. 如果没有原始链接 (来自 YAML 解析)，则构建
    try {
        if (node.type === 'vmess') {
            const vmessObj = {
                v: "2", ps: node.name, add: node.server, port: node.port, id: node.uuid,
                aid: 0, scy: node.cipher || "auto", net: node.network || "tcp", type: "none", tls: node.tls ? "tls" : ""
            };
            if (node['ws-opts']) {
                vmessObj.net = "ws";
                vmessObj.path = node['ws-opts'].path;
                if (node['ws-opts'].headers && node['ws-opts'].headers.Host) vmessObj.host = node['ws-opts'].headers.Host;
            }
            return 'vmess://' + safeBase64Encode(JSON.stringify(vmessObj));
        }

        if (node.type === 'vless' || node.type === 'trojan') {
            const params = new URLSearchParams();
            params.set('security', node.tls ? (node.reality ? 'reality' : 'tls') : 'none');
            if (node.network) params.set('type', node.network);
            if (node.flow) params.set('flow', node.flow);
            if (node.sni || node.servername) params.set('sni', node.sni || node.servername);
            if (node['client-fingerprint']) params.set('fp', node['client-fingerprint']);
            
            if (node.network === 'ws' && node['ws-opts']) {
                if (node['ws-opts'].path) params.set('path', node['ws-opts'].path);
                if (node['ws-opts'].headers && node['ws-opts'].headers.Host) params.set('host', node['ws-opts'].headers.Host);
            }
            if (node.reality && node.reality.publicKey) {
                params.set('pbk', node.reality.publicKey);
                if (node.reality.shortId) params.set('sid', node.reality.shortId);
            }
            const userInfo = (node.type === 'vless') ? node.uuid : (node.password || node.uuid);
            return `${node.type}://${userInfo}@${node.server}:${node.port}?${params.toString()}#${safeName}`;
        }

        if (node.type === 'hysteria2') {
            const params = new URLSearchParams();
            if (node.sni) params.set('sni', node.sni);
            if (node['skip-cert-verify']) params.set('insecure', '1');
            if (node.obfs) { params.set('obfs', node.obfs); if (node['obfs-password']) params.set('obfs-password', node['obfs-password']); }
            return `hysteria2://${node.password}@${node.server}:${node.port}?${params.toString()}#${safeName}`;
        }
        
        if (node.type === 'ss') {
             const userPart = safeBase64Encode(`${node.cipher}:${node.password}`);
             return `ss://${userPart}@${node.server}:${node.port}#${safeName}`;
        }
    } catch (e) {}
    return '';
}

// --- 核心：万能解析器 (暴力版) ---
const parseNodesCommon = (text) => {
    const nodes = [];
    const rawSet = new Set(); // 用于去重

    // 辅助：添加节点
    const addNode = (n) => {
        if (!n.link) n.link = generateNodeLink(n);
        if (n.link && n.link.length > 15 && !rawSet.has(n.link)) {
            rawSet.add(n.link);
            nodes.push(n);
        }
    }

    // 1. 尝试解码
    let decoded = deepBase64Decode(text);
    // 如果解码后变成了空串，或包含乱码，回退到原文
    if (!decoded || decoded.length < 5 || /[\x00-\x08]/.test(decoded)) decoded = text;

    // 2. 暴力提取：正则表达式扫描全文 (应对非标准格式、混合内容)
    // 匹配所有标准链接格式
    const linkRegex = /(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive):\/\/[^\s\n"']+/gi;
    const matches = decoded.match(linkRegex);
    
    if (matches) {
        for (const match of matches) {
            const trimLine = match.trim();
            try {
                let node = { origLink: trimLine, type: 'raw' };
                if (trimLine.startsWith('vmess://')) {
                    const b64 = trimLine.substring(8);
                    const c = JSON.parse(safeBase64Decode(b64));
                    node.name = c.ps; node.type = 'vmess';
                } else {
                    try {
                        const url = new URL(trimLine);
                        node.name = decodeURIComponent(url.hash.substring(1));
                        node.type = url.protocol.replace(':', '');
                        node.server = url.hostname;
                        node.port = url.port;
                    } catch(e) {
                        // 如果 URL 解析失败，正则提取 Name
                        const m = trimLine.match(/#(.*?)$/);
                        if(m) node.name = decodeURIComponent(m[1]);
                    }
                }
                if (!node.name) node.name = 'Node';
                addNode(node);
            } catch(e) {}
        }
    }

    // 3. 如果暴力提取没找到多少节点，且内容像 YAML，则尝试结构化解析 (作为补充)
    if (nodes.length < 1 && (decoded.includes('proxies:') || decoded.includes('name:'))) {
        try {
            const lines = decoded.split(/\r?\n/);
            let inProxyBlock = false;
            let currentBlock = [];

            const processYamlBlock = (block) => {
                const getVal = (k) => {
                    const reg = new RegExp(`${k}:\\s*(?:['"](.*?)['"]|(.*?))(?:$|#|,|})`, 'i');
                    const line = block.find(l => reg.test(l));
                    if (!line) return undefined;
                    const m = line.match(reg);
                    return (m[1] || m[2]).trim();
                };
                
                let type = getVal('type');
                if (!type || ['url-test', 'selector', 'fallback', 'direct', 'reject', 'load-balance'].includes(type)) return;

                const node = {
                    name: getVal('name'), type, server: getVal('server'), port: getVal('port'),
                    uuid: getVal('uuid'), cipher: getVal('cipher'), password: getVal('password'),
                    udp: getVal('udp') === 'true', tls: getVal('tls') === 'true',
                    "skip-cert-verify": getVal('skip-cert-verify') === 'true',
                    servername: getVal('servername') || getVal('sni'), sni: getVal('sni'),
                    network: getVal('network'), flow: getVal('flow'),
                    "client-fingerprint": getVal('client-fingerprint')
                };

                // WS 和 Reality 参数提取 (简化版，直接在 block 里找)
                const findInBlock = (key) => {
                    const line = block.find(l => l.includes(key));
                    if(!line) return undefined;
                    const m = line.match(/:\s*(?:['"](.*?)['"]|(.*?))$/);
                    return m ? (m[1]||m[2]).trim() : undefined;
                }

                if(node.network === 'ws' || block.some(l=>l.includes('ws-opts'))) {
                    node.network = 'ws';
                    node['ws-opts'] = { 
                        path: findInBlock('path') || '/', 
                        headers: { Host: findInBlock('Host') || '' } 
                    };
                }
                if(block.some(l=>l.includes('public-key'))) {
                    node.tls = true;
                    node.reality = { publicKey: findInBlock('public-key'), shortId: findInBlock('short-id') };
                }

                if (node.server && node.port) addNode(node);
            }

            for (const line of lines) {
                if (!line.trim() || line.trim().startsWith('#')) continue;
                if (line.includes('proxies:')) { inProxyBlock = true; continue; }
                if (inProxyBlock) {
                    if (line.trim().startsWith('-') && line.includes('name:')) {
                        if (currentBlock.length > 0) processYamlBlock(currentBlock);
                        currentBlock = [line];
                    } else if (currentBlock.length > 0) {
                        currentBlock.push(line);
                    }
                    // 如果缩进回到顶部，或者遇到其他顶级块，结束
                    if (!line.startsWith(' ') && !line.startsWith('-') && !line.includes('proxies:')) {
                        inProxyBlock = false;
                        if (currentBlock.length > 0) processYamlBlock(currentBlock);
                        currentBlock = [];
                    }
                }
            }
            if (currentBlock.length > 0) processYamlBlock(currentBlock);
        } catch (e) {}
    }

    return nodes;
}

// --- API 路由 ---
app.get('/g/:token', async (c) => {
    const token = c.req.param('token');
    try {
        const group = await c.env.DB.prepare("SELECT * FROM groups WHERE token = ? AND status = 1").bind(token).first();
        if (!group) return c.text('Invalid Group Token', 404);
        const config = JSON.parse(group.config || '[]');
        
        let allNodes = [];
        for (const item of config) {
            const sub = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE id = ?").bind(item.subId).first();
            if (!sub) continue; 
            
            let content = "";
            if (sub.type === 'node') { content = sub.url; } 
            else {
                const res = await fetchWithSmartUA(sub.url);
                if (res && res.ok) content = res.prefetchedText || await res.text();
            }
            if (!content) continue;

            const nodes = parseNodesCommon(content);
            let allowed = 'all';
            if (item.include && Array.isArray(item.include) && item.include.length > 0) allowed = new Set(item.include);

            for (const node of nodes) {
                if (allowed !== 'all' && !allowed.has(node.name)) continue;
                
                let name = node.name.trim();
                let i = 1;
                while (allNodes.some(n => n.name === name)) name = `${node.name} ${i++}`;
                node.name = name;
                node.link = generateNodeLink(node);
                allNodes.push(node);
            }
        }

        const links = allNodes.map(n => n.link).join('\n');
        return c.text(safeBase64Encode(links), 200, { 'Content-Type': 'text/plain; charset=utf-8' });
    } catch(e) { return c.text(e.message, 500); }
})

// --- 资源管理 ---
app.get('/subs', async (c) => { 
    const {results} = await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY sort_order ASC, id DESC").all(); 
    return c.json({success:true, data:results.map(i=>{ try { i.info = JSON.parse(i.info); } catch(e) { i.info = {}; } return i; })}) 
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

// --- 聚合组管理 ---
app.get('/groups', async (c) => { const {results} = await c.env.DB.prepare("SELECT * FROM groups ORDER BY sort_order ASC, id DESC").all(); return c.json({success:true, data:results.map(g => ({...g, config: JSON.parse(g.config||'[]')}))}) })
app.post('/groups', async (c) => { const b=await c.req.json(); await c.env.DB.prepare("INSERT INTO groups (name, token, config, status, sort_order) VALUES (?, ?, ?, 1, 0)").bind(b.name, generateToken(), JSON.stringify(b.config||[])).run(); return c.json({success:true}) })
app.put('/groups/:id', async (c) => {
    const b = await c.req.json(); const id = c.req.param('id');
    let parts = ["updated_at=CURRENT_TIMESTAMP"]; let args = [];
    if(b.name!==undefined){parts.push("name=?");args.push(b.name)} if(b.config!==undefined){parts.push("config=?");args.push(JSON.stringify(b.config))}
    if(b.status!==undefined){parts.push("status=?");args.push(parseInt(b.status))} if(b.refresh_token){parts.push("token=?");args.push(generateToken())}
    const query = `UPDATE groups SET ${parts.join(', ')} WHERE id=?`; args.push(id);
    await c.env.DB.prepare(query).bind(...args).run(); return c.json({success:true})
})
app.delete('/groups/:id', async (c) => { await c.env.DB.prepare("DELETE FROM groups WHERE id=?").bind(c.req.param('id')).run(); return c.json({success:true}) })

// --- Check / Login ---
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
app.get('/settings', async(c)=>{return c.json({success:true,data:{}})}); app.post('/settings', async(c)=>{return c.json({success:true})})
app.post('/backup/import', async (c) => { 
    const {items, groups}=await c.req.json(); 
    if(items) { const s=c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, params, status, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)"); await c.env.DB.batch(items.map(i=>s.bind(i.name,i.url,i.type||'subscription',JSON.stringify(i.info),JSON.stringify({}),i.status??1,i.sort_order??0))); }
    if(groups) { const s=c.env.DB.prepare("INSERT INTO groups (name, token, config, status, sort_order) VALUES (?, ?, ?, ?, ?)"); await c.env.DB.batch(groups.map(g=>s.bind(g.name, g.token, JSON.stringify(g.config), g.status??1, g.sort_order??0))); }
    return c.json({success:true}) 
})

export const onRequest = handle(app)
