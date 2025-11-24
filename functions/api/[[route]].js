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
        const decoded = new TextDecoder('utf-8').decode(Uint8Array.from(atob(safeStr), c => c.charCodeAt(0)));
        if (decoded.includes('://') || decoded.includes('proxies:') || decoded.includes('server:')) return decoded;
        return deepBase64Decode(decoded, depth + 1);
    } catch (e) { return str; }
}
const safeStr = (str) => {
    if (!str) return '""'
    const s = String(str).trim()
    if (/[:#\[\]\{\},&*!|>'%@]/.test(s) || /^\s|\s$/.test(s)) return JSON.stringify(s)
    return s
}

// --- 核心：生成标准的 Clash YAML 节点 ---
const fmtClashProxy = (node) => {
    const props = [
        `name: ${safeStr(node.name)}`,
        `type: ${node.type}`,
        `server: ${safeStr(node.server)}`,
        `port: ${node.port}`
    ];

    // 通用字段
    if (node.uuid) props.push(`uuid: ${safeStr(node.uuid)}`);
    if (node.password) props.push(`password: ${safeStr(node.password)}`);
    if (node.cipher) props.push(`cipher: ${node.cipher}`);
    if (node.udp !== undefined) props.push(`udp: ${node.udp}`);
    if (node["skip-cert-verify"] !== undefined) props.push(`skip-cert-verify: ${node["skip-cert-verify"]}`);
    if (node.tfo !== undefined) props.push(`tfo: ${node.tfo}`);

    // TLS 相关
    if (node.tls) {
        props.push(`tls: true`);
        if (node.servername) props.push(`servername: ${safeStr(node.servername)}`);
        if (node.alpn && node.alpn.length > 0) props.push(`alpn: [${node.alpn.map(a => `"${a}"`).join(', ')}]`);
        if (node["client-fingerprint"]) props.push(`client-fingerprint: ${node["client-fingerprint"]}`);
    }

    // REALITY 专用
    if (node.reality) {
        props.push(`flow: ${node.flow || 'xtls-rprx-vision'}`);
        props.push(`reality-opts:`);
        props.push(`  public-key: ${node.reality.publicKey}`);
        if (node.reality.shortId) props.push(`  short-id: ${node.reality.shortId}`);
    } else if (node.flow) {
        props.push(`flow: ${node.flow}`); // 普通 VLESS flow
    }

    // 网络相关 (ws, grpc, tcp)
    if (node.network) {
        props.push(`network: ${node.network}`);
        if (node.network === 'ws' && node['ws-opts']) {
            props.push(`ws-opts:`);
            props.push(`  path: ${safeStr(node['ws-opts'].path)}`);
            if (node['ws-opts'].headers && node['ws-opts'].headers.Host) {
                props.push(`  headers:`);
                props.push(`    Host: ${safeStr(node['ws-opts'].headers.Host)}`);
            }
        }
        if (node.network === 'grpc' && node['grpc-opts']) {
            props.push(`grpc-opts:`);
            props.push(`  grpc-service-name: ${safeStr(node['grpc-opts']['grpc-service-name'])}`);
        }
    }

    // Trojan 专用
    if (node.type === 'trojan') {
        if (node.sni) props.push(`sni: ${safeStr(node.sni)}`);
    }

    // Hysteria2 专用
    if (node.type === 'hysteria2') {
        if (node.sni) props.push(`sni: ${safeStr(node.sni)}`);
        if (node.obfs) {
            props.push(`obfs: ${node.obfs}`);
            if (node['obfs-password']) props.push(`obfs-password: ${safeStr(node['obfs-password'])}`);
        }
    }

    // TUIC 专用
    if (node.type === 'tuic') {
        if (node.sni) props.push(`sni: ${safeStr(node.sni)}`);
        if (node['udp-relay-mode']) props.push(`udp-relay-mode: ${node['udp-relay-mode']}`);
        if (node['congestion-controller']) props.push(`congestion-controller: ${node['congestion-controller']}`);
    }

    // 缩进处理 (所有属性增加 2 个空格)
    return props.map(line => '  ' + line).join('\n');
}

// --- 核心：生成标准的 节点链接 (V2RayN/Nekobox) ---
const generateNodeLink = (node) => {
    try {
        const safe = (s) => encodeURIComponent(s || '');
        // VMess (JSON)
        if (node.type === 'vmess') {
            const vmessObj = {
                v: "2", ps: node.name, add: node.server, port: node.port, id: node.uuid,
                aid: 0, scy: "auto", net: node.network || "tcp", type: "none", host: "", path: "", tls: node.tls ? "tls" : ""
            };
            if (node["ws-opts"]) {
                vmessObj.net = "ws";
                vmessObj.path = node["ws-opts"].path;
                if (node["ws-opts"].headers) vmessObj.host = node["ws-opts"].headers.Host;
            }
            if (node.flow) vmessObj.flow = node.flow; // Vision
            return 'vmess://' + safeBase64Encode(JSON.stringify(vmessObj));
        }
        // VLESS / Trojan / Hysteria2 / Tuic
        if (['vless', 'trojan', 'hysteria2', 'tuic'].includes(node.type)) {
            let auth = node.uuid || node.password || '';
            let link = `${node.type}://${auth}@${node.server}:${node.port}?`;
            let params = [];
            
            if (node.type !== 'hysteria2' && node.type !== 'tuic') {
               params.push(`encryption=none`); // vless/trojan standard
            }
            
            if (node.tls) params.push(`security=tls`);
            else if (node.type === 'vless' && !node.tls) params.push(`security=none`); // vless tcp
            
            if (node.type === 'trojan' && node.sni) params.push(`sni=${safe(node.sni)}`);
            if (node.type === 'vless' || node.type === 'trojan') params.push(`type=${node.network || 'tcp'}`);

            // Common params
            if (node.servername) params.push(`sni=${safe(node.servername)}`);
            if (node.flow) params.push(`flow=${node.flow}`);
            if (node['client-fingerprint']) params.push(`fp=${node['client-fingerprint']}`);
            if (node['skip-cert-verify']) params.push(`allowInsecure=1`); // Standard param name

            // WS
            if (node.network === 'ws' && node['ws-opts']) {
                if (node['ws-opts'].path) params.push(`path=${safe(node['ws-opts'].path)}`);
                if (node['ws-opts'].headers?.Host) params.push(`host=${safe(node['ws-opts'].headers.Host)}`);
            }

            // Reality
            if (node.reality) {
                params.push(`security=reality`);
                params.push(`pbk=${safe(node.reality.publicKey)}`);
                params.push(`sid=${safe(node.reality.shortId)}`);
            }

            // Hysteria2
            if (node.type === 'hysteria2') {
                if (node.sni) params.push(`sni=${safe(node.sni)}`);
                if (node.obfs) {
                    params.push(`obfs=${node.obfs}`);
                    params.push(`obfs-password=${safe(node['obfs-password'])}`);
                }
            }

            // Tuic
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
        // SS
        if (node.type === 'ss') {
            let authStr = `${node.cipher}:${node.password}`;
            return `ss://${safeBase64Encode(authStr)}@${node.server}:${node.port}#${safe(node.name)}`;
        }
        return node.link;
    } catch (e) { return ''; }
}

// --- 核心：解析节点 ---
const parseNodesCommon = (text) => {
    let nodes = [];
    let decoded = deepBase64Decode(text);
    
    // 强制每种协议换行
    const splitText = decoded.replace(/(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//gi, '\n$1://');
    const lines = splitText.split(/\r?\n/);
    
    for (const line of lines) {
        const trimLine = line.trim();
        if (!trimLine || trimLine.length < 10) continue;
        
        try {
            // VMess
            if (trimLine.startsWith('vmess://')) {
                const c = JSON.parse(safeBase64Decode(trimLine.substring(8)));
                nodes.push({
                    name: c.ps, type: 'vmess', server: c.add, port: c.port, uuid: c.id, alterId: c.aid,
                    cipher: c.scy||'auto', network: c.net, tls: c.tls==='tls',
                    "ws-opts": c.net==='ws' ? { path: c.path, headers: { Host: c.host } } : undefined,
                    flow: c.flow, link: trimLine
                });
                continue;
            }
            
            // URL Scheme based
            if (/^(vless|ss|trojan|hysteria2?|tuic):\/\//i.test(trimLine)) {
                const url = new URL(trimLine);
                const params = url.searchParams;
                const protocol = url.protocol.replace(':', '');
                
                let node = {
                    name: decodeURIComponent(url.hash.substring(1)),
                    type: protocol === 'hysteria' ? 'hysteria2' : protocol,
                    server: url.hostname,
                    port: url.port,
                    link: trimLine
                };

                // Auth
                if (url.username) {
                    if (protocol === 'ss') {
                        // SS special case base64
                        try {
                            const decodedAuth = safeBase64Decode(url.username);
                            if (decodedAuth.includes(':')) {
                                const [m, p] = decodedAuth.split(':');
                                node.cipher = m; node.password = p;
                            } else {
                                node.cipher = url.username; node.password = url.password; // Plain
                            }
                        } catch(e) { node.cipher = url.username; node.password = url.password; }
                    } else {
                        node.uuid = url.username; // VLESS/TUIC
                        node.password = url.password || url.username; // Trojan/Hy2
                    }
                }

                // Standard Query Params
                node.tls = params.get('security') === 'tls' || params.get('encryption') === 'ssl' || protocol === 'hysteria2' || protocol === 'tuic';
                node.network = params.get('type') || 'tcp';
                node.sni = params.get('sni');
                node.servername = params.get('sni') || params.get('host');
                node['skip-cert-verify'] = params.get('allowInsecure') === '1' || params.get('insecure') === '1';
                node.flow = params.get('flow');
                node['client-fingerprint'] = params.get('fp');
                if (params.get('alpn')) node.alpn = [params.get('alpn')];

                // WS
                if (node.network === 'ws') {
                    node['ws-opts'] = {
                        path: params.get('path') || '/',
                        headers: { Host: params.get('host') || node.servername }
                    };
                }

                // Reality
                if (params.get('security') === 'reality') {
                    node.tls = true; // Reality implies TLS logic in Clash
                    node.reality = {
                        publicKey: params.get('pbk'),
                        shortId: params.get('sid')
                    };
                    // Ensure fingerprint is set for Reality
                    if (!node['client-fingerprint']) node['client-fingerprint'] = 'chrome'; 
                }
                
                // Hysteria2
                if (node.type === 'hysteria2') {
                    node.obfs = params.get('obfs');
                    node['obfs-password'] = params.get('obfs-password');
                    // Hy2 usually implies udp: true
                    node.udp = true; 
                }

                // TUIC
                if (node.type === 'tuic') {
                    node['congestion-controller'] = params.get('congestion_control');
                    node['udp-relay-mode'] = params.get('udp_relay_mode');
                    node.udp = true;
                }
                
                // Special fixes based on standard yaml
                if (node.type === 'vless' && node.network === 'ws') node.udp = true;
                if (node.type === 'trojan' && node.network === 'ws') node.udp = true;

                nodes.push(node);
            }
        } catch(e) {}
    }
    return nodes;
}


// --- 路由 ---

app.get('/subscribe/clash', async (c) => {
    try {
        const token = c.req.query('token')
        if (token !== c.env.ADMIN_PASSWORD) return c.text('Unauthorized', 401)
        
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
                // Fetch logic inline to simplify
                try {
                    const ua = 'ClashMeta/1.0';
                    const res = await fetch(sub.url, { headers: { 'User-Agent': ua } });
                    if(res.ok) content = await res.text();
                } catch(e){}
            }
            const nodes = parseNodesCommon(content);
            
            // Name handling
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

        // Generate YAML Block
        const proxiesStr = allNodes.map(node => `  - ${fmtClashProxy(node).trim()}`).join('\n');
        const groupsStr = allNodes.map(node => `      - ${node.name}`).join('\n');
        
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
    // Re-implement simplified getAllNodes logic inline to avoid dep issues
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
            let params = {}; try { params = JSON.parse(sub.params) } catch(e) {}
            const allowed = params.include?.length ? new Set(params.include) : null;
            
            for (const node of nodes) {
                if (allowed && !allowed.has(node.name)) continue;
                // Re-generate standard link
                links.push(generateNodeLink(node));
            }
        }
        return c.text(btoa(encodeURIComponent(links.join('\n')).replace(/%([0-9A-F]{2})/g, (m, p1) => String.fromCharCode('0x' + p1))))
    } catch(e) { return c.text(e.message, 500) }
})

// CRUD / Check / Login (保留原始简单逻辑，或按需更新)
app.post('/check', async (c) => {
    const { url } = await c.req.json();
    try {
        const res = await fetch(url, { headers: { 'User-Agent': 'ClashMeta/1.0' } });
        if(!res.ok) throw new Error(res.status);
        const text = await res.text();
        const nodes = parseNodesCommon(text);
        
        // Mock stats
        let stats = null;
        const info = res.headers.get('subscription-userinfo');
        if(info) {
             const parts = {}; info.split(';').forEach(p => { const [k,v]=p.split('='); if(k&&v) parts[k.trim()]=Number(v) });
             if(parts.total) stats = { total: formatBytes(parts.total), used: formatBytes((parts.upload||0)+(parts.download||0)), expire: parts.expire ? new Date(parts.expire*1000).toLocaleDateString() : '长期' };
        }
        return c.json({ success: true, data: { valid: true, nodeCount: nodes.length, stats } });
    } catch(e) { return c.json({ success: false, error: e.message }) }
})

// Standard CRUD
app.get('/subs', async (c) => { const {results} = await c.env.DB.prepare("SELECT * FROM subscriptions").all(); return c.json({success:true, data:results}) })
app.post('/subs', async (c) => { const b=await c.req.json(); await c.env.DB.prepare("INSERT INTO subscriptions (name,url,type,params,info,sort_order,status) VALUES (?,?,?,?,?,0,1)").bind(b.name,b.url,b.type||'sub',JSON.stringify(b.params||{}),'{}').run(); return c.json({success:true}) })
app.put('/subs/:id', async (c) => { const b=await c.req.json(); await c.env.DB.prepare("UPDATE subscriptions SET name=?, url=?, params=? WHERE id=?").bind(b.name,b.url,JSON.stringify(b.params||{}), c.req.param('id')).run(); return c.json({success:true}) })
app.delete('/subs/:id', async (c) => { await c.env.DB.prepare("DELETE FROM subscriptions WHERE id=?").bind(c.req.param('id')).run(); return c.json({success:true}) })
app.post('/login', async (c) => { const {password}=await c.req.json(); return c.json({success: password===c.env.ADMIN_PASSWORD}) })
app.get('/template/default', async (c) => { return c.json({success:true, data: ""}) }) // Placeholder

export const onRequest = handle(app)
