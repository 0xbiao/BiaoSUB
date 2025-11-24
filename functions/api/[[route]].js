import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono().basePath('/api')
app.use('/*', cors())

// --- 鉴权 ---
app.use('/*', async (c, next) => {
  const path = c.req.path
  if (path.endsWith('/login') || path.includes('/subscribe')) return await next()
  const authHeader = c.req.header('Authorization')
  if (authHeader !== c.env.ADMIN_PASSWORD) return c.json({ success: false, error: 'Unauthorized' }, 401)
  await next()
})
app.onError((err, c) => c.json({ error: err.message }, 500))

// --- 工具 ---
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
        if (clean.includes('proxies:')) return str;
        let safeStr = clean.replace(/-/g, '+').replace(/_/g, '/');
        while (safeStr.length % 4) safeStr += '=';
        const decoded = new TextDecoder('utf-8').decode(Uint8Array.from(atob(safeStr), c => c.charCodeAt(0)));
        if (decoded.includes('://') || decoded.includes('proxies:')) return deepBase64Decode(decoded, depth + 1);
        return decoded;
    } catch (e) { return str; }
}
const safeStr = (str) => JSON.stringify(String(str || ''))

// --- 核心：Clash 节点生成 (修复缩进) ---
const fmtClashProxy = (node) => {
    let lines = [];
    lines.push(`  - name: ${safeStr(node.name)}`);
    lines.push(`    type: ${node.type}`);
    lines.push(`    server: ${safeStr(node.server)}`);
    lines.push(`    port: ${node.port}`);
    
    if (node.uuid) lines.push(`    uuid: ${safeStr(node.uuid)}`);
    if (node.password) lines.push(`    password: ${safeStr(node.password)}`);
    if (node.cipher) lines.push(`    cipher: ${node.cipher}`);
    if (node.udp) lines.push(`    udp: true`);
    if (node["skip-cert-verify"]) lines.push(`    skip-cert-verify: true`);
    
    if (node.tls) {
        lines.push(`    tls: true`);
        if (node.servername) lines.push(`    servername: ${safeStr(node.servername)}`);
        if (node["client-fingerprint"]) lines.push(`    client-fingerprint: ${node["client-fingerprint"]}`);
    }

    if (node.reality) {
        lines.push(`    flow: ${node.flow || 'xtls-rprx-vision'}`);
        lines.push(`    reality-opts:`);
        lines.push(`      public-key: ${safeStr(node.reality.publicKey)}`);
        lines.push(`      short-id: ${safeStr(node.reality.shortId)}`);
    } else if (node.flow) {
        lines.push(`    flow: ${node.flow}`);
    }

    if (node.network) {
        lines.push(`    network: ${node.network}`);
        if (node.network === 'ws' && node['ws-opts']) {
            lines.push(`    ws-opts:`);
            lines.push(`      path: ${safeStr(node['ws-opts'].path)}`);
            if (node['ws-opts'].headers?.Host) {
                lines.push(`      headers:`);
                lines.push(`        Host: ${safeStr(node['ws-opts'].headers.Host)}`);
            }
        }
    }

    if (node.type === 'trojan' && node.sni) lines.push(`    sni: ${safeStr(node.sni)}`);
    if (node.type === 'hysteria2') {
        if (node.sni) lines.push(`    sni: ${safeStr(node.sni)}`);
        if (node.obfs) {
            lines.push(`    obfs: ${node.obfs}`);
            lines.push(`    obfs-password: ${safeStr(node['obfs-password'])}`);
        }
    }
    if (node.type === 'tuic') {
        if (node.sni) lines.push(`    sni: ${safeStr(node.sni)}`);
        if (node.alpn) lines.push(`    alpn: [${node.alpn.map(a=>`"${a}"`).join(', ')}]`);
        lines.push(`    udp-relay-mode: native`);
        lines.push(`    congestion-controller: bbr`);
    }

    return lines.join('\n');
}

// --- 解析器 (强化正则，支持自建节点多行) ---
const parseNodesCommon = (text) => {
    let nodes = [];
    let decoded = deepBase64Decode(text);
    
    // 1. 尝试 YAML
    const yamlMatch = decoded.match(/proxies:\s*([\s\S]*?)(?:proxy-groups:|rules:|$)/);
    if (yamlMatch) {
        // 简易 YAML 解析
        const block = yamlMatch[1];
        const lines = block.split(/\r?\n/);
        let current = null;
        for (const line of lines) {
            if (line.trim().startsWith('- name:')) {
                if (current) nodes.push(current);
                current = {};
            }
            if (!current) continue;
            const parts = line.trim().replace(/^- /, '').split(':');
            if (parts.length >= 2) {
                const key = parts[0].trim();
                let val = parts.slice(1).join(':').trim().replace(/^['"]|['"]$/g, '');
                if (key === 'name' || key === 'server' || key === 'type' || key === 'uuid' || key === 'password' || key === 'cipher' || key === 'sni') {
                    current[key] = val;
                }
                if (key === 'port') current.port = parseInt(val);
                if (key === 'udp') current.udp = val === 'true';
                if (key === 'tls') current.tls = val === 'true';
            }
        }
        if (current) nodes.push(current);
    }

    // 2. 尝试通用链接 (VMess/VLESS/etc)
    // 修复：先用换行符分割，再逐行处理，避免正则死锁
    const lines = decoded.split(/[\r\n]+/);
    for (const line of lines) {
        const trimLine = line.trim();
        if (!trimLine) continue;
        
        try {
            if (trimLine.startsWith('vmess://')) {
                const c = JSON.parse(safeBase64Decode(trimLine.substring(8)));
                nodes.push({ name: c.ps, type: 'vmess', server: c.add, port: c.port, uuid: c.id, cipher: c.scy||'auto', network: c.net, tls: c.tls==='tls', "ws-opts": c.net==='ws' ? { path: c.path, headers: { Host: c.host } } : undefined, flow: c.flow });
            } 
            else if (/^(vless|ss|trojan|hysteria2?|tuic):\/\//i.test(trimLine)) {
                const url = new URL(trimLine);
                const params = url.searchParams;
                const protocol = url.protocol.replace(':', '');
                let node = {
                    name: decodeURIComponent(url.hash.substring(1)),
                    type: protocol === 'hysteria' ? 'hysteria2' : protocol,
                    server: url.hostname,
                    port: parseInt(url.port),
                    uuid: url.username,
                    password: url.password || url.username,
                    tls: params.get('security') === 'tls' || protocol === 'hysteria2' || protocol === 'tuic',
                    network: params.get('type') || 'tcp',
                    sni: params.get('sni'),
                    servername: params.get('sni'),
                    "skip-cert-verify": params.get('allowInsecure') === '1',
                    flow: params.get('flow'),
                    "client-fingerprint": params.get('fp')
                };
                if (protocol === 'ss') {
                     try { const d = safeBase64Decode(url.username); if (d.includes(':')) { const [m, p] = d.split(':'); node.cipher = m; node.password = p; } } catch(e){}
                }
                if (node.network === 'ws') node['ws-opts'] = { path: params.get('path'), headers: { Host: params.get('host') } };
                if (params.get('security') === 'reality') { node.tls = true; node.reality = { publicKey: params.get('pbk'), shortId: params.get('sid') }; }
                if (protocol === 'hysteria2') { node.obfs = params.get('obfs'); node['obfs-password'] = params.get('obfs-password'); node.udp = true; }
                if (protocol === 'tuic') { node.alpn = [params.get('alpn')||'h3']; node.udp = true; }
                
                nodes.push(node);
            }
        } catch(e) {}
    }
    
    // 生成 link 字段 (给前端用)
    return nodes.map(n => {
        if (!n.link) {
            // 简单重建 link 用于预览
            n.link = `${n.type}://${n.server}:${n.port}#${encodeURIComponent(n.name)}`; 
        }
        return n;
    });
}

// --- 路由 ---

// A. Clash 订阅 (支持自定义模板)
app.get('/subscribe/clash', async (c) => {
    try {
        const token = c.req.query('token')
        if (token !== c.env.ADMIN_PASSWORD) return c.text('Unauthorized', 401)
        
        const { results: subs } = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE status = 1").all()
        
        let allNodes = []
        let customTemplate = null

        for (const sub of subs) {
            // 优先获取用户自定义的模板 (取第一个非空的)
            let params = {}; try { params = JSON.parse(sub.params) } catch(e) {}
            if (!customTemplate && params.template && params.template.trim().length > 10) {
                customTemplate = params.template;
            }

            let content = "";
            if (sub.type === 'node') content = sub.url;
            else {
                try {
                    const res = await fetch(sub.url, { headers: { 'User-Agent': 'ClashMeta/1.0' } });
                    if(res.ok) content = await res.text();
                } catch(e){}
            }
            const nodes = parseNodesCommon(content);
            for(const node of nodes) {
                let name = node.name.trim();
                let i = 1;
                while (allNodes.some(n => n.name === name)) name = `${node.name} ${i++}`;
                node.name = name;
                allNodes.push(node);
            }
        }

        const proxiesStr = allNodes.map(node => fmtClashProxy(node)).join('\n');
        const groupsStr = allNodes.map(node => `      - ${safeStr(node.name)}`).join('\n');

        // 最终模板组装
        let finalYaml = "";
        if (customTemplate) {
            finalYaml = customTemplate
                .replace(/<PROXIES>|<BIAOSUB_PROXIES>/g, proxiesStr)
                .replace(/<PROXY_GROUPS>|<BIAOSUB_GROUP_ALL>/g, groupsStr);
        } else {
            // 默认极简模板
            finalYaml = `port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: '0.0.0.0:9090'
proxies:
${proxiesStr}
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
${groupsStr}
rules:
  - MATCH,🚀 节点选择`;
        }

        return c.text(finalYaml, 200, { 
            'Content-Type': 'text/yaml; charset=utf-8',
            'Content-Disposition': 'attachment; filename="biaosub.yaml"'
        })
    } catch(e) { return c.text(e.message, 500) }
})

// B. Base64 (保持原样)
app.get('/subscribe/base64', async (c) => {
    try {
        const token = c.req.query('token')
        if (token !== c.env.ADMIN_PASSWORD) return c.text('Unauthorized', 401)
        const { results: subs } = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE status = 1").all()
        let links = [];
        for (const sub of subs) {
             let content = "";
            if (sub.type === 'node') content = sub.url;
            else { try { const res = await fetch(sub.url, {headers:{'User-Agent':'v2rayNG/1.8.5'}}); if(res.ok) content = await res.text(); } catch(e){} }
            const nodes = parseNodesCommon(content);
            for (const node of nodes) links.push(node.link);
        }
        return c.text(btoa(encodeURIComponent(links.join('\n')).replace(/%([0-9A-F]{2})/g, (m, p1) => String.fromCharCode('0x' + p1))))
    } catch(e) { return c.text(e.message, 500) }
})

// C. Check (修复自建节点和预览)
app.post('/check', async (c) => {
    const { url, type } = await c.req.json();
    try {
        let content = "";
        let stats = null;
        if (type === 'node') {
            content = url;
        } else {
            const res = await fetch(url, { headers: { 'User-Agent': 'ClashMeta/1.0' } });
            if(!res.ok) throw new Error(`HTTP ${res.status}`);
            content = await res.text();
            const info = res.headers.get('subscription-userinfo');
            if(info) {
                 const parts = {}; info.split(';').forEach(p => { const [k,v]=p.split('='); if(k&&v) parts[k.trim()]=Number(v) });
                 if(parts.total && parts.total > 0) {
                     const used = (parts.upload||0)+(parts.download||0);
                     stats = { 
                         total: formatBytes(parts.total), 
                         used: formatBytes(used), 
                         percent: Math.round((used/parts.total)*100),
                         expire: parts.expire ? new Date(parts.expire*1000).toLocaleDateString() : '长期' 
                     };
                 }
            }
        }
        const nodes = parseNodesCommon(content);
        return c.json({ success: true, data: { valid: true, nodeCount: nodes.length, stats, nodes } });
    } catch(e) { return c.json({ success: false, error: e.message }) }
})

// CRUD
app.get('/subs', async (c) => { const {results}=await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY sort_order ASC, id DESC").all(); return c.json({success:true, data:results.map(i=>{try{i.info=JSON.parse(i.info);i.params=JSON.parse(i.params)}catch(e){}return i})}) })
app.post('/subs', async (c) => { const b=await c.req.json(); await c.env.DB.prepare("INSERT INTO subscriptions (name,url,type,params,info,sort_order,status) VALUES (?,?,?,?,?,0,1)").bind(b.name,b.url,b.type||'sub',JSON.stringify(b.params||{}),'{}').run(); return c.json({success:true}) })
app.put('/subs/:id', async (c) => { const b=await c.req.json(); let q="UPDATE subscriptions SET updated_at=CURRENT_TIMESTAMP"; const a=[]; for(const k of ['name','url','status','type'])if(b[k]!==undefined){q+=`, ${k}=?`;a.push(b[k])}; if(b.params){q+=`, params=?`;a.push(JSON.stringify(b.params))}; if(b.info){q+=`, info=?`;a.push(JSON.stringify(b.info))}; q+=" WHERE id=?"; a.push(c.req.param('id')); await c.env.DB.prepare(q).bind(...a).run(); return c.json({success:true}) })
app.delete('/subs/:id', async (c) => { await c.env.DB.prepare("DELETE FROM subscriptions WHERE id=?").bind(c.req.param('id')).run(); return c.json({success:true}) })
app.post('/sort', async (c) => { const {ids}=await c.req.json(); const s=c.env.DB.prepare("UPDATE subscriptions SET sort_order=? WHERE id=?"); await c.env.DB.batch(ids.map((id,i)=>s.bind(i,id))); return c.json({success:true}) })
app.post('/backup/import', async (c) => { const {items}=await c.req.json(); const s=c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, params, status, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)"); await c.env.DB.batch(items.map(i=>s.bind(i.name,i.url,i.type||'subscription',JSON.stringify(i.info),JSON.stringify(i.params),i.status??1,i.sort_order??0))); return c.json({success:true}) })
app.post('/login', async (c) => { const {password}=await c.req.json(); return c.json({success: password===c.env.ADMIN_PASSWORD}) })

export const onRequest = handle(app)
