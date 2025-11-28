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

const deepBase64Decode = (str, depth = 0) => {
    if (depth > 3) return str;
    if (!str || typeof str !== 'string') return str;
    try {
        const clean = str.replace(/\s/g, '');
        if (clean.length < 10 || /[^A-Za-z0-9+/=_]/.test(clean)) return str;
        let safeStr = clean.replace(/-/g, '+').replace(/_/g, '/');
        while (safeStr.length % 4) safeStr += '=';
        let binary; try { binary = atob(safeStr); } catch(e) { return str; }
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        const decoded = new TextDecoder('utf-8').decode(bytes);
        if (decoded.includes('://') || decoded.includes('proxies:') || decoded.includes('server:') || decoded.includes('vmess://')) {
            return deepBase64Decode(decoded, depth + 1);
        }
        if (/[\x00-\x08\x0E-\x1F]/.test(decoded)) return str;
        return decoded;
    } catch (e) { return str; }
}

// --- 核心：智能 Fetch (混合抓取模式) ---
const extractUserInfo = (headers) => {
    let infoStr = null;
    headers.forEach((val, key) => { if (key.toLowerCase().includes('userinfo')) infoStr = val; });
    if (!infoStr) return null;
    const info = {};
    const parts = infoStr.split(/;|,\s*/);
    parts.forEach(part => { const [key, value] = part.trim().split('='); if (key && value) info[key.trim().toLowerCase()] = Number(value); });
    if (!info.total && !info.upload && !info.download) return null;
    const usedRaw = (info.upload || 0) + (info.download || 0); const totalRaw = info.total || 0;
    return {
        used: formatBytes(usedRaw), total: totalRaw ? formatBytes(totalRaw) : '无限制',
        expire: info.expire ? new Date(info.expire * 1000).toLocaleDateString() : '长期',
        percent: totalRaw ? Math.min(100, Math.round(usedRaw / totalRaw * 100)) : 0,
        raw_total: totalRaw, raw_used: usedRaw, raw_expire: info.expire
    };
}

const fetchWithSmartUA = async (url) => {
  const userAgents = ['v2rayNG/1.8.5', 'ClashMeta/1.0', 'Mozilla/5.0'];
  let validRes = null; let foundInfo = null;
  for (const ua of userAgents) {
    try {
      const controller = new AbortController(); const id = setTimeout(() => controller.abort(), 12000);
      const res = await fetch(url, { headers: { 'User-Agent': ua }, signal: controller.signal, cache: 'no-store' });
      clearTimeout(id);
      if (res.ok) {
        if (!foundInfo) foundInfo = extractUserInfo(res.headers);
        if (!validRes) {
            const clone = res.clone(); const text = await clone.text();
            if (text.length > 50 && !text.includes('<!DOCTYPE html>')) {
                Object.defineProperty(clone, 'prefetchedText', { value: text, writable: true });
                validRes = clone;
            }
        }
        if (validRes && foundInfo) break;
      }
    } catch (e) {}
  }
  if (validRes) { if (foundInfo) Object.defineProperty(validRes, 'trafficInfo', { value: foundInfo, writable: true }); return validRes; }
  return null;
}

// --- 核心：生成链接 ---
const generateNodeLink = (node) => {
    const safeName = encodeURIComponent(node.name || 'Node');
    if (node.origLink) {
        try {
            if (node.origLink.startsWith('vmess://')) {
                const base64Part = node.origLink.substring(8);
                const jsonStr = safeBase64Decode(base64Part);
                const vmessObj = JSON.parse(jsonStr);
                vmessObj.ps = node.name; 
                return 'vmess://' + safeBase64Encode(JSON.stringify(vmessObj));
            }
            const hashIndex = node.origLink.lastIndexOf('#');
            if (hashIndex !== -1) return node.origLink.substring(0, hashIndex) + '#' + safeName;
            return node.origLink + '#' + safeName;
        } catch(e) { return node.origLink; }
    }
    try {
        if (node.type === 'vmess') {
            const vmessObj = {
                v: "2", ps: node.name, add: node.server, port: node.port, id: node.uuid,
                aid: 0, scy: node.cipher || "auto", net: node.network || "tcp", type: "none", tls: node.tls ? "tls" : ""
            };
            if (node['ws-opts']) {
                vmessObj.net = "ws"; vmessObj.path = node['ws-opts'].path;
                if (node['ws-opts'].headers && node['ws-opts'].headers.Host) vmessObj.host = node['ws-opts'].headers.Host;
            }
            return 'vmess://' + safeBase64Encode(JSON.stringify(vmessObj));
        }
        if (node.type === 'vless' || node.type === 'trojan') {
            const params = new URLSearchParams();
            params.set('security', node.tls ? (node.reality ? 'reality' : 'tls') : 'none');
            if (node.network) params.set('type', node.network); if (node.flow) params.set('flow', node.flow);
            if (node.sni || node.servername) params.set('sni', node.sni || node.servername);
            if (node['client-fingerprint']) params.set('fp', node['client-fingerprint']);
            if (node.network === 'ws' && node['ws-opts']) {
                if (node['ws-opts'].path) params.set('path', node['ws-opts'].path);
                if (node['ws-opts'].headers && node['ws-opts'].headers.Host) params.set('host', node['ws-opts'].headers.Host);
            }
            if (node.reality && node.reality.publicKey) {
                params.set('pbk', node.reality.publicKey); if (node.reality.shortId) params.set('sid', node.reality.shortId);
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

// --- 核心：Clash Meta 转换器 (修复版) ---
const toClashProxy = (node) => {
    try {
        if (!node.name || !node.server || !node.port) return null;
        const common = `  - name: ${node.name}
    server: ${node.server}
    port: ${node.port}`;
        
        if (node.type === 'ss') {
            if (!node.cipher || !node.password) return null;
            return `${common}
    type: ss
    cipher: ${node.cipher}
    password: ${node.password}`;
        }
        if (node.type === 'trojan') {
            if (!node.password) return null;
            let res = `${common}
    type: trojan
    password: ${node.password}
    skip-cert-verify: ${node['skip-cert-verify'] || false}`;
            if (node.sni || node.servername) res += `\n    sni: ${node.sni || node.servername}`;
            if (node.network === 'ws') {
                res += `\n    network: ws\n    ws-opts:\n      path: ${node['ws-opts']?.path || '/'}`;
                if (node['ws-opts']?.headers?.Host) res += `\n      headers:\n        Host: ${node['ws-opts'].headers.Host}`;
            }
            if (node.udp) res += `\n    udp: true`;
            return res;
        }
        if (node.type === 'vmess') {
            if (!node.uuid) return null;
            let res = `${common}
    type: vmess
    uuid: ${node.uuid}
    alterId: 0
    cipher: ${node.cipher || 'auto'}
    tls: ${node.tls ? true : false}
    skip-cert-verify: ${node['skip-cert-verify'] || false}`;
            if (node.network === 'ws') {
                res += `
    network: ws
    ws-opts:
      path: ${node['ws-opts']?.path || '/'}
      headers:
        Host: ${node['ws-opts']?.headers?.Host || ''}`;
            }
            return res;
        }
        if (node.type === 'vless') {
            if (!node.uuid) return null;
            let res = `${common}
    type: vless
    uuid: ${node.uuid}
    tls: ${node.tls ? true : false}
    skip-cert-verify: ${node['skip-cert-verify'] || false}
    network: ${node.network || 'tcp'}`;
            if (node.flow) res += `\n    flow: ${node.flow}`;
            if (node.sni || node.servername) res += `\n    servername: ${node.sni || node.servername}`;
            if (node['client-fingerprint']) res += `\n    client-fingerprint: ${node['client-fingerprint']}`;
            if (node.reality && node.reality.publicKey) {
                res += `\n    reality-opts:
      public-key: ${node.reality.publicKey}
      short-id: ${node.reality.shortId || ''}`;
            }
            if (node.network === 'ws') {
                res += `
    ws-opts:
      path: ${node['ws-opts']?.path || '/'}
      headers:
        Host: ${node['ws-opts']?.headers?.Host || ''}`;
            }
            return res;
        }
        if (node.type === 'hysteria2') {
            let res = `${common}
    type: hysteria2
    skip-cert-verify: ${node['skip-cert-verify'] || false}`;
            if (node.password) res += `\n    password: ${node.password}`;
            if (node.sni) res += `\n    sni: ${node.sni}`;
            if (node.obfs) {
                res += `\n    obfs: ${node.obfs}`;
                if (node['obfs-password']) res += `\n    obfs-password: ${node['obfs-password']}`;
            }
            return res;
        }
        return null;
    } catch(e) { return null; }
}

// --- 核心：万能解析器 (增强版：修复自建节点解析不全) ---
const parseNodesCommon = (text) => {
    const nodes = [];
    const rawSet = new Set(); 
    const addNode = (n) => {
        if (!n.name) n.name = 'Node';
        // 确保关键字段存在，否则 Clash 转换器会丢弃
        if (!n.link) n.link = generateNodeLink(n);
        if (n.link && n.link.length > 15 && !rawSet.has(n.link)) {
            rawSet.add(n.link); nodes.push(n);
        }
    }
    let decoded = deepBase64Decode(text);
    if (!decoded || decoded.length < 5 || /[\x00-\x08]/.test(decoded)) decoded = text;

    // 1. 处理以换行分隔的 URI Scheme (vmess://, vless:// 等)
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
                    // 关键修复：从 JSON 完整解析 vmess 字段，供 Clash 使用
                    node.server = c.add; node.port = c.port; node.uuid = c.id;
                    node.cipher = c.scy || "auto"; node.tls = c.tls === "tls";
                    node.network = c.net;
                    if (c.net === 'ws') {
                        node['ws-opts'] = { path: c.path || '/', headers: { Host: c.host || '' } };
                    }
                } else {
                    const url = new URL(trimLine);
                    node.name = decodeURIComponent(url.hash.substring(1));
                    node.type = url.protocol.replace(':', '');
                    // 处理用户信息 (user:pass 或 user)
                    if (url.username) {
                        if (node.type === 'vmess' || node.type === 'vless') node.uuid = url.username;
                        else if (node.type === 'ss') {
                            // ss://base64@...
                            if (!url.password && url.username.includes(':')) {
                                // 极少数未编码情况
                                const p = url.username.split(':'); node.cipher = p[0]; node.password = p[1];
                            } else {
                                // 尝试解码
                                try {
                                    const userPart = safeBase64Decode(url.username);
                                    if (userPart.includes(':')) {
                                        const p = userPart.split(':'); node.cipher = p[0]; node.password = p[1];
                                    }
                                } catch(e) { node.password = url.username; }
                            }
                        }
                        else node.password = url.username;
                    }
                    node.server = url.hostname; node.port = url.port;
                    
                    // 解析参数
                    const params = url.searchParams;
                    if (params.has('sni')) node.sni = params.get('sni');
                    if (params.has('peer')) node.sni = params.get('peer');
                    if (params.has('security')) node.tls = params.get('security') === 'tls';
                    if (params.has('type')) node.network = params.get('type');
                    if (params.has('flow')) node.flow = params.get('flow');
                    if (params.has('fp')) node['client-fingerprint'] = params.get('fp');
                    if (params.has('path')) {
                        if (!node['ws-opts']) node['ws-opts'] = {};
                        node['ws-opts'].path = params.get('path');
                    }
                    if (params.has('host')) {
                        if (!node['ws-opts']) node['ws-opts'] = {};
                        if (!node['ws-opts'].headers) node['ws-opts'].headers = {};
                        node['ws-opts'].headers.Host = params.get('host');
                    }
                }
                addNode(node);
            } catch(e) {}
        }
    }

    // 2. 处理 Clash YAML 格式 (如果 URI 提取失败或数量很少)
    if (nodes.length < 1 && (decoded.includes('proxies:') || decoded.includes('name:'))) {
        try {
            const lines = decoded.split(/\r?\n/);
            let inProxyBlock = false; let currentBlock = [];
            const processYamlBlock = (block) => {
                const getVal = (k) => {
                    const reg = new RegExp(`${k}:\\s*(?:['"](.*?)['"]|(.*?))(?:$|#|,|})`, 'i');
                    const line = block.find(l => reg.test(l));
                    if (!line) return undefined;
                    const m = line.match(reg); return (m[1] || m[2]).trim();
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
                const findInBlock = (key) => {
                    const line = block.find(l => l.includes(key)); if(!line) return undefined;
                    const m = line.match(new RegExp(`${key}:\\s*(?:['"](.*?)['"]|([^\\s{]+))`)); 
                    return m ? (m[1]||m[2]).trim() : undefined;
                }
                if(node.network === 'ws' || block.some(l=>l.includes('ws-opts'))) {
                    node.network = 'ws';
                    node['ws-opts'] = { path: findInBlock('path') || '/', headers: { Host: findInBlock('Host') || '' } };
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
                    } else if (currentBlock.length > 0) currentBlock.push(line);
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

// --- 核心路由 ---
app.get('/g/:token', async (c) => {
    const token = c.req.param('token');
    const format = c.req.query('format') || 'base64';
    
    try {
        const group = await c.env.DB.prepare("SELECT * FROM groups WHERE token = ? AND status = 1").bind(token).first();
        if (!group) return c.text('Invalid Group Token', 404);
        
        const baseConfig = JSON.parse(group.config || '[]');
        const clashConfig = group.clash_config ? JSON.parse(group.clash_config) : { mode: 'generate' };
        
        // 设置文件名 (Clash Verge 等客户端会读取此文件名)
        const filename = encodeURIComponent(group.name || 'GroupConfig');
        c.header('Content-Disposition', `attachment; filename*=UTF-8''${filename}.yaml; filename="${filename}.yaml"`);
        c.header('Subscription-Userinfo', 'upload=0; download=0; total=1073741824000000; expire=0');

        // 1. Raw YAML Mode: 直接返回托管的 YAML 内容
        if (format === 'clash' && clashConfig.mode === 'raw') {
            return c.text(clashConfig.raw_yaml || "", 200, { 'Content-Type': 'text/yaml; charset=utf-8' });
        }

        // 2. Generate Mode
        let targetConfig = baseConfig;
        if (format === 'clash' && clashConfig.resources && clashConfig.resources.length > 0) {
            targetConfig = clashConfig.resources;
        }

        let allNodes = [];
        const allNodeNamesSet = new Set();

        for (const item of targetConfig) {
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
                
                // Deterministic Deduplication: 保证名称唯一且稳定
                let name = node.name.trim();
                let i = 1; 
                let originalName = name;
                while (allNodeNamesSet.has(name)) {
                    name = `${originalName} ${i++}`;
                }
                node.name = name;
                allNodeNamesSet.add(name);

                node.link = generateNodeLink(node);
                allNodes.push(node);
            }
        }

        if (format === 'clash') {
            if (!clashConfig) return c.text("Clash config not found.", 404);
            
            let yaml = (clashConfig.header || "") + "\n\nproxies:\n";
            const generatedNodeNames = new Set();
            
            // Generate Proxies
            for (const node of allNodes) {
                const proxyYaml = toClashProxy(node);
                if (proxyYaml) {
                    yaml += proxyYaml + "\n";
                    generatedNodeNames.add(node.name);
                }
            }

            // Generate Groups (Strict Filter)
            yaml += "\nproxy-groups:\n";
            if (clashConfig.groups && Array.isArray(clashConfig.groups)) {
                for (const g of clashConfig.groups) {
                    yaml += `  - name: ${g.name}\n    type: ${g.type}\n    proxies:\n`;
                    if (g.proxies && Array.isArray(g.proxies)) {
                        g.proxies.forEach(p => {
                            if (generatedNodeNames.has(p) || ['DIRECT', 'REJECT', 'NO-RESOLVE'].includes(p)) {
                                yaml += `      - ${p}\n`;
                            }
                        });
                    }
                }
            }
            yaml += "\n" + (clashConfig.rules || "");
            return c.text(yaml, 200, { 'Content-Type': 'text/yaml; charset=utf-8' });
        }

        const links = allNodes.map(n => n.link).join('\n');
        return c.text(safeBase64Encode(links), 200, { 'Content-Type': 'text/plain; charset=utf-8' });
    } catch(e) { return c.text(e.message, 500); }
})

// --- API Endpoints ---
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
app.get('/groups', async (c) => { 
    const {results} = await c.env.DB.prepare("SELECT * FROM groups ORDER BY sort_order ASC, id DESC").all(); 
    return c.json({success:true, data:results.map(g => ({
        ...g, 
        config: JSON.parse(g.config||'[]'),
        clash_config: g.clash_config ? JSON.parse(g.clash_config) : { mode: 'generate', header: "", groups: [], rules: "", resources: [], raw_yaml: "" }
    }))}) 
})
app.post('/groups', async (c) => { 
    const b=await c.req.json(); 
    const token = generateToken();
    const clashConfig = b.clash_config || { mode: 'generate', header: "", groups: [], rules: "", resources: [], raw_yaml: "" };
    await c.env.DB.prepare("INSERT INTO groups (name, token, config, clash_config, status, sort_order) VALUES (?, ?, ?, ?, 1, 0)")
        .bind(b.name, token, JSON.stringify(b.config||[]), JSON.stringify(clashConfig)).run(); 
    return c.json({success:true}) 
})
app.put('/groups/:id', async (c) => {
    const b = await c.req.json(); const id = c.req.param('id');
    let parts = ["updated_at=CURRENT_TIMESTAMP"]; let args = [];
    if(b.name!==undefined){parts.push("name=?");args.push(b.name)} 
    if(b.config!==undefined){parts.push("config=?");args.push(JSON.stringify(b.config))}
    if(b.clash_config!==undefined){parts.push("clash_config=?");args.push(JSON.stringify(b.clash_config))}
    if(b.status!==undefined){parts.push("status=?");args.push(parseInt(b.status))}
    if(b.refresh_token){parts.push("token=?");args.push(generateToken())}
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
