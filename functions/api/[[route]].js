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

app.onError((err, c) => {
  console.error(err)
  return c.json({ error: err.message }, 500)
})

// --- 工具函数 ---
const formatBytes = (bytes) => {
  if (!bytes || isNaN(bytes)) return '0 B'
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
const safeBase64Encode = (str) => {
    try { return btoa(unescape(encodeURIComponent(str))); } catch (e) { return btoa(str); }
}
const deepBase64Decode = (str, depth = 0) => {
    if (depth > 3) return str;
    if (!str || typeof str !== 'string') return str;
    try {
        const clean = str.replace(/\s/g, '');
        if (!/^[A-Za-z0-9+/=_:-]+$/.test(clean) || clean.length < 10) return str;
        if (clean.includes('proxies:') || clean.includes('mixed-port:')) return str;
        let safeStr = clean.replace(/-/g, '+').replace(/_/g, '/');
        while (safeStr.length % 4) safeStr += '=';
        const binary = atob(safeStr);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        const decoded = new TextDecoder('utf-8').decode(bytes);
        if (decoded.includes('://') || decoded.includes('proxies:') || decoded.includes('server:')) return deepBase64Decode(decoded, depth + 1);
        return decoded;
    } catch (e) { return str; }
}
const safeStr = (str) => {
    if (!str && str !== 0) return '""'
    return JSON.stringify(String(str))
}

// --- 核心：生成标准的 Clash YAML 节点 (修复缩进问题) ---
const fmtClashProxy = (node) => {
    let lines = [];
    lines.push(`  - name: ${safeStr(node.name)}`);
    lines.push(`    type: ${node.type}`);
    lines.push(`    server: ${safeStr(node.server)}`);
    lines.push(`    port: ${node.port}`);
    
    if (node.uuid) lines.push(`    uuid: ${safeStr(node.uuid)}`);
    if (node.password) lines.push(`    password: ${safeStr(node.password)}`);
    if (node.cipher) lines.push(`    cipher: ${node.cipher}`);
    if (node.udp !== undefined) lines.push(`    udp: ${node.udp}`);
    if (node["skip-cert-verify"] !== undefined) lines.push(`    skip-cert-verify: ${node["skip-cert-verify"]}`);
    if (node.tfo !== undefined) lines.push(`    tfo: ${node.tfo}`);

    // TLS
    if (node.tls) {
        lines.push(`    tls: true`);
        if (node.servername) lines.push(`    servername: ${safeStr(node.servername)}`);
        if (node.alpn && node.alpn.length > 0) lines.push(`    alpn: [${node.alpn.map(a => `"${a}"`).join(', ')}]`);
        if (node["client-fingerprint"]) lines.push(`    client-fingerprint: ${node["client-fingerprint"]}`);
    }

    // Reality (注意缩进层级)
    if (node.reality) {
        lines.push(`    flow: ${node.flow || 'xtls-rprx-vision'}`);
        lines.push(`    reality-opts:`);
        lines.push(`      public-key: ${safeStr(node.reality.publicKey)}`);
        if (node.reality.shortId) lines.push(`      short-id: ${safeStr(node.reality.shortId)}`);
    } else if (node.flow) {
        lines.push(`    flow: ${node.flow}`);
    }

    // Network
    if (node.network) {
        lines.push(`    network: ${node.network}`);
        if (node.network === 'ws' && node['ws-opts']) {
            lines.push(`    ws-opts:`);
            lines.push(`      path: ${safeStr(node['ws-opts'].path)}`);
            if (node['ws-opts'].headers && node['ws-opts'].headers.Host) {
                lines.push(`      headers:`);
                lines.push(`        Host: ${safeStr(node['ws-opts'].headers.Host)}`);
            }
        }
        if (node.network === 'grpc' && node['grpc-opts']) {
            lines.push(`    grpc-opts:`);
            lines.push(`      grpc-service-name: ${safeStr(node['grpc-opts']['grpc-service-name'])}`);
        }
    }

    // Specific Types
    if (node.type === 'trojan' && node.sni) lines.push(`    sni: ${safeStr(node.sni)}`);
    
    if (node.type === 'hysteria2') {
        if (node.sni) lines.push(`    sni: ${safeStr(node.sni)}`);
        if (node.obfs) {
            lines.push(`    obfs: ${node.obfs}`);
            if (node['obfs-password']) lines.push(`    obfs-password: ${safeStr(node['obfs-password'])}`);
        }
    }

    if (node.type === 'tuic') {
        if (node.sni) lines.push(`    sni: ${safeStr(node.sni)}`);
        if (node['udp-relay-mode']) lines.push(`    udp-relay-mode: ${node['udp-relay-mode']}`);
        if (node['congestion-controller']) lines.push(`    congestion-controller: ${node['congestion-controller']}`);
    }

    return lines.join('\n');
}

// --- 核心：生成标准链接 (确保前端能用) ---
const generateNodeLink = (node) => {
    try {
        const safe = (s) => encodeURIComponent(s || '');
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
        if (['vless', 'trojan', 'hysteria2', 'tuic'].includes(node.type)) {
            let auth = node.uuid || node.password || '';
            let link = `${node.type}://${auth}@${node.server}:${node.port}?`;
            let params = [];
            if (node.type !== 'hysteria2' && node.type !== 'tuic') params.push(`encryption=none`);
            if (node.tls) params.push(`security=tls`);
            else if (node.type === 'vless') params.push(`security=none`);
            
            if (node.type === 'trojan' && node.sni) params.push(`sni=${safe(node.sni)}`);
            if (node.type === 'vless' || node.type === 'trojan') params.push(`type=${node.network || 'tcp'}`);
            if (node.servername) params.push(`sni=${safe(node.servername)}`);
            if (node.flow) params.push(`flow=${node.flow}`);
            if (node['client-fingerprint']) params.push(`fp=${node['client-fingerprint']}`);
            if (node['skip-cert-verify']) params.push(`allowInsecure=1`);
            
            if (node.network === 'ws' && node['ws-opts']) {
                if (node['ws-opts'].path) params.push(`path=${safe(node['ws-opts'].path)}`);
                if (node['ws-opts'].headers?.Host) params.push(`host=${safe(node['ws-opts'].headers.Host)}`);
            }
            if (node.reality) {
                params.push(`security=reality`);
                params.push(`pbk=${safe(node.reality.publicKey)}`);
                params.push(`sid=${safe(node.reality.shortId)}`);
            }
            if (node.type === 'hysteria2') {
                if (node.sni) params.push(`sni=${safe(node.sni)}`);
                if (node.obfs) {
                    params.push(`obfs=${node.obfs}`);
                    params.push(`obfs-password=${safe(node['obfs-password'])}`);
                }
            }
            if (node.type === 'tuic') {
                if (node.sni) params.push(`sni=${safe(node.sni)}`);
                if (node['congestion-controller']) params.push(`congestion_control=${node['congestion-controller']}`);
                if (node['udp-relay-mode']) params.push(`udp_relay_mode=${node['udp-relay-mode']}`);
                if (node.alpn) params.push(`alpn=${safe(node.alpn[0])}`);
            }
            link += params.join('&');
            link += `#${safe(node.name)}`;
            return link;
        }
        if (node.type === 'ss') {
            return `ss://${safeBase64Encode(`${node.cipher}:${node.password}`)}@${node.server}:${node.port}#${safe(node.name)}`;
        }
        return node.link || '';
    } catch (e) { return ''; }
}

// --- 解析器 ---

const parseYamlProxies = (content) => {
    const nodes = [];
    if (!content) return nodes;
    const lines = content.split(/\r?\n/);
    let inProxyBlock = false;
    
    const parseLineObj = (line) => {
        const getVal = (k) => {
            const reg = new RegExp(`${k}:\\s*(?:['"](.*?)['"]|(.*?))(?:$|,|\\}|\\n)`, 'i');
            const m = line.match(reg);
            return m ? (m[1] || m[2]).trim() : undefined;
        };
        let type = getVal('type');
        let server = getVal('server');
        let port = getVal('port');
        let name = getVal('name');
        
        if (!type && line.includes('ss')) type = 'ss';
        if (!type && line.includes('vmess')) type = 'vmess';
        
        if (type && server && port) {
             const node = {
                name: name || `${type}-${server}`,
                type, server, port,
                cipher: getVal('cipher'), uuid: getVal('uuid'), password: getVal('password'),
                tls: line.includes('tls: true') || getVal('tls') === 'true',
                "skip-cert-verify": line.includes('skip-cert-verify: true'),
                servername: getVal('servername') || getVal('sni'),
                sni: getVal('sni'),
                network: getVal('network'),
                "ws-opts": undefined
            };
            if (node.network === 'ws') {
                node["ws-opts"] = { path: getVal('path')||'/', headers: { Host: getVal('host')||'' } };
            }
            node.link = generateNodeLink(node); // 生成标准链接
            nodes.push(node);
        }
    }

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        if (/^(proxies|Proxy):/i.test(line)) { inProxyBlock = true; continue; }
        if (/^(proxy-groups|rules|rule-providers):/i.test(line)) { inProxyBlock = false; break; }
        if (inProxyBlock && line.startsWith('-')) {
             if (line.includes('name:') && line.includes('server:')) {
                 parseLineObj(line);
             } else {
                 let temp = line;
                 let j = 1;
                 while (i + j < lines.length && !lines[i+j].trim().startsWith('-')) { temp += " " + lines[i+j].trim(); j++; }
                 parseLineObj(temp);
             }
        }
    }
    return nodes;
}

const parseNodesCommon = (text) => {
    let nodes = [];
    let decoded = deepBase64Decode(text);
    
    if (decoded.includes('proxies:') || decoded.includes('Proxy:') || decoded.includes('- name:')) {
        const yamlNodes = parseYamlProxies(decoded);
        if (yamlNodes.length > 0) return yamlNodes;
    }

    const splitText = decoded.replace(/(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//gi, '\n$1://');
    const lines = splitText.split(/\r?\n/);
    
    for (const line of lines) {
        const trimLine = line.trim();
        if (!trimLine || trimLine.length < 10) continue;
        
        try {
            if (trimLine.startsWith('vmess://')) {
                const c = JSON.parse(safeBase64Decode(trimLine.substring(8)));
                nodes.push({ name: c.ps, type: 'vmess', server: c.add, port: c.port, uuid: c.id, cipher: c.scy||'auto', network: c.net, tls: c.tls==='tls', "ws-opts": c.net==='ws' ? { path: c.path, headers: { Host: c.host } } : undefined, flow: c.flow, link: trimLine });
                continue;
            }
            if (/^(vless|ss|trojan|hysteria2?|tuic):\/\//i.test(trimLine)) {
                const url = new URL(trimLine);
                const params = url.searchParams;
                const protocol = url.protocol.replace(':', '');
                let node = { name: decodeURIComponent(url.hash.substring(1)), type: protocol==='hysteria'?'hysteria2':protocol, server: url.hostname, port: url.port, link: trimLine };
                
                if (url.username) {
                    if (protocol === 'ss') {
                        try { const d = safeBase64Decode(url.username); if (d.includes(':')) { const [m, p] = d.split(':'); node.cipher = m; node.password = p; } else { node.cipher = url.username; node.password = url.password; } } catch(e) { node.cipher = url.username; node.password = url.password; }
                    } else { node.uuid = url.username; node.password = url.password || url.username; }
                }

                node.tls = params.get('security')==='tls' || params.get('encryption')==='ssl' || protocol==='hysteria2' || protocol==='tuic';
                node.network = params.get('type') || 'tcp';
                node.sni = params.get('sni');
                node.servername = node.sni || params.get('host');
                node['skip-cert-verify'] = params.get('allowInsecure')==='1'||params.get('insecure')==='1';
                node.flow = params.get('flow');
                node['client-fingerprint'] = params.get('fp');
                if (params.get('alpn')) node.alpn = [params.get('alpn')];

                if (node.network === 'ws') node['ws-opts'] = { path: params.get('path')||'/', headers: { Host: params.get('host')||node.servername } };
                if (params.get('security') === 'reality') { node.tls = true; node.reality = { publicKey: params.get('pbk'), shortId: params.get('sid') }; if(!node['client-fingerprint']) node['client-fingerprint']='chrome'; }
                if (node.type === 'hysteria2') { node.obfs = params.get('obfs'); node['obfs-password'] = params.get('obfs-password'); node.udp=true; }
                if (node.type === 'tuic') { node['congestion-controller'] = params.get('congestion_control'); node['udp-relay-mode'] = params.get('udp_relay_mode'); node.udp=true; }
                if ((node.type === 'vless' || node.type === 'trojan') && node.network === 'ws') node.udp = true;

                nodes.push(node);
            }
        } catch(e) {}
    }
    return nodes;
}

// --- 路由 ---

// A. Clash 订阅
app.get('/subscribe/clash', async (c) => {
    try {
        const token = c.req.query('token')
        if (token !== c.env.ADMIN_PASSWORD) return c.text('Unauthorized', 401)
        
        // 默认模板 (你提供的标准)
        let template = `port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: false
bind-address: '*'
mode: rule
log-level: info
ipv6: true
external-controller: '127.0.0.1:9090'
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver: ['223.5.5.5', '119.29.29.29']
  fallback: ['https://1.0.0.1/dns-query', 'https://9.9.9.10/dns-query']
proxies:
<BIAOSUB_PROXIES>
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ♻️ 自动选择
<BIAOSUB_GROUP_ALL>
  - name: ♻️ 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
<BIAOSUB_GROUP_ALL>
rules:
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择`;
        
        try {
            const { results } = await c.env.DB.prepare("SELECT content FROM templates WHERE is_default = 1 LIMIT 1").all()
            if (results.length > 0) template = results[0].content
        } catch(e) {}

        const { results: subs } = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC").all()
        let allNodes = []
        for (const sub of subs) {
            let content = "";
            if (sub.type === 'node') content = sub.url;
            else {
                try {
                    const res = await fetch(sub.url, { headers: { 'User-Agent': 'ClashMeta/1.0' } });
                    if(res.ok) content = await res.text();
                } catch(e){}
            }
            const nodes = parseNodesCommon(content);
            let params = {}; try { params = sub.params ? JSON.parse(sub.params) : {} } catch(e) {}
            const allowed = params.include?.length ? new Set(params.include) : null;
            for(const node of nodes) {
                if (allowed && !allowed.has(node.name)) continue;
                let name = node.name.trim();
                let i = 1;
                while (allNodes.some(n => n.name === name)) name = `${node.name} ${i++}`;
                node.name = name;
                allNodes.push(node);
            }
        }
        if (allNodes.length === 0) {
            allNodes.push({name: "无可用节点", type: "ss", server: "127.0.0.1", port: 1080, cipher: "aes-128-gcm", password: "error"});
        }

        // 使用修复后的 fmtClashProxy 生成 YAML
        const proxiesStr = allNodes.map(node => fmtClashProxy(node)).join('\n');
        const groupsStr = allNodes.map(node => `      - ${safeStr(node.name)}`).join('\n');
        
        const finalYaml = template
            .replace(/<BIAOSUB_PROXIES>/g, proxiesStr)
            .replace(/<BIAOSUB_GROUP_ALL>/g, groupsStr);

        return c.text(finalYaml, 200, { 
            'Content-Type': 'text/yaml; charset=utf-8',
            'Content-Disposition': 'attachment; filename="biaosub.yaml"'
        })
    } catch(e) { return c.text(e.message, 500) }
})

// B. Base64
app.get('/subscribe/base64', async (c) => {
    try {
        const token = c.req.query('token')
        if (token !== c.env.ADMIN_PASSWORD) return c.text('Unauthorized', 401)
        const { results: subs } = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC").all()
        let links = [];
        for (const sub of subs) {
             let content = "";
            if (sub.type === 'node') content = sub.url;
            else { try { const res = await fetch(sub.url, {headers:{'User-Agent':'v2rayNG/1.8.5'}}); if(res.ok) content = await res.text(); } catch(e){} }
            const nodes = parseNodesCommon(content);
            let params = {}; try { params = JSON.parse(sub.params) } catch(e) {}
            const allowed = params.include?.length ? new Set(params.include) : null;
            for (const node of nodes) {
                if (allowed && !allowed.has(node.name)) continue;
                links.push(generateNodeLink(node));
            }
        }
        return c.text(btoa(encodeURIComponent(links.join('\n')).replace(/%([0-9A-F]{2})/g, (m, p1) => String.fromCharCode('0x' + p1))))
    } catch(e) { return c.text(e.message, 500) }
})

// C. Check 接口 (修复：确保返回完整节点信息，解决功能按钮失效)
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
                 if(parts.total) stats = { total: formatBytes(parts.total), used: formatBytes((parts.upload||0)+(parts.download||0)), expire: parts.expire ? new Date(parts.expire*1000).toLocaleDateString() : '长期' };
            }
        }

        const rawNodes = parseNodesCommon(content);
        // 关键修复：确保每个节点都有 link 属性，并且生成完整结构给前端
        const nodes = rawNodes.map(n => ({
            ...n,
            link: generateNodeLink(n) // 强制重生成标准链接，确保前端功能可用
        }));

        return c.json({ success: true, data: { valid: true, nodeCount: nodes.length, stats, nodes } });
    } catch(e) { return c.json({ success: false, error: e.message }) }
})

// CRUD
app.get('/subs', async (c) => { 
    const {results} = await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY sort_order ASC, id DESC").all(); 
    return c.json({success:true, data:results.map(i=>{try{i.info=JSON.parse(i.info);i.params=JSON.parse(i.params)}catch(e){}return i})}) 
})
app.post('/subs', async (c) => { const b=await c.req.json(); await c.env.DB.prepare("INSERT INTO subscriptions (name,url,type,params,info,sort_order,status) VALUES (?,?,?,?,?,0,1)").bind(b.name,b.url,b.type||'sub',JSON.stringify(b.params||{}),'{}').run(); return c.json({success:true}) })
app.put('/subs/:id', async (c) => { 
    const b=await c.req.json(); 
    let q="UPDATE subscriptions SET updated_at=CURRENT_TIMESTAMP"; const a=[]
    for(const k of ['name','url','status','type'])if(b[k]!==undefined){q+=`, ${k}=?`;a.push(b[k])}
    if(b.info){q+=`, info=?`;a.push(JSON.stringify(b.info))}
    if(b.params){q+=`, params=?`;a.push(JSON.stringify(b.params))}
    q+=" WHERE id=?"; a.push(c.req.param('id')); await c.env.DB.prepare(q).bind(...a).run()
    return c.json({success:true}) 
})
app.delete('/subs/:id', async (c) => { await c.env.DB.prepare("DELETE FROM subscriptions WHERE id=?").bind(c.req.param('id')).run(); return c.json({success:true}) })
app.post('/sort', async (c) => { const {ids}=await c.req.json(); const s=c.env.DB.prepare("UPDATE subscriptions SET sort_order=? WHERE id=?"); await c.env.DB.batch(ids.map((id,i)=>s.bind(i,id))); return c.json({success:true}) })
app.post('/backup/import', async (c) => { const {items}=await c.req.json(); const s=c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, params, status, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)"); await c.env.DB.batch(items.map(i=>s.bind(i.name,i.url,i.type||'subscription',JSON.stringify(i.info),JSON.stringify(i.params),i.status??1,i.sort_order??0))); return c.json({success:true}) })
app.get('/settings', async(c)=>{return c.json({success:true,data:{}})}) 
app.post('/settings', async(c)=>{return c.json({success:true})})
app.post('/login', async (c) => { const {password}=await c.req.json(); return c.json({success: password===c.env.ADMIN_PASSWORD}) })
app.get('/template/default', async (c) => { const {results}=await c.env.DB.prepare("SELECT content FROM templates WHERE is_default=1").all(); return c.json({success:true, data: results[0]?.content||""}) })
app.post('/template/default', async (c) => { const {content}=await c.req.json(); await c.env.DB.prepare("UPDATE templates SET content=? WHERE is_default=1").bind(content).run(); return c.json({success:true}) })

export const onRequest = handle(app)
