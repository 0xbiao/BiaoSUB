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
        if (clean.includes('proxies:') || clean.includes('mixed-port:') || clean.includes('proxy-groups:')) return str;
        let safeStr = clean.replace(/-/g, '+').replace(/_/g, '/');
        while (safeStr.length % 4) safeStr += '=';
        const decoded = new TextDecoder('utf-8').decode(Uint8Array.from(atob(safeStr), c => c.charCodeAt(0)));
        if (decoded.includes('://') || decoded.includes('proxies:') || decoded.includes('server:')) return deepBase64Decode(decoded, depth + 1);
        return decoded;
    } catch (e) { return str; }
}
const safeStr = (str) => JSON.stringify(String(str || ''))

// --- 核心：智能 Fetch ---
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
      const res = await fetch(url, { headers: { 'User-Agent': ua }, signal: controller.signal });
      clearTimeout(id);
      if (res.ok) {
        const clone = res.clone();
        const text = await clone.text();
        if (text.includes('<!DOCTYPE html>') || text.includes('<html')) continue;
        const info = extractUserInfo(res.headers);
        if (info) {
            Object.defineProperty(res, 'trafficInfo', { value: info, writable: true });
            Object.defineProperty(res, 'prefetchedText', { value: text, writable: true });
            return res;
        }
        if (!bestRes) {
            bestRes = res;
            Object.defineProperty(bestRes, 'prefetchedText', { value: text, writable: true });
        }
      }
    } catch (e) {}
  }
  return bestRes;
}

// --- 核心：Clash 节点生成 ---
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
    if (node.tfo) lines.push(`    tfo: true`);
    
    if (node.tls) {
        lines.push(`    tls: true`);
        if (node.servername) lines.push(`    servername: ${safeStr(node.servername)}`);
        if (node.alpn && node.alpn.length > 0) lines.push(`    alpn: [${node.alpn.map(a => `"${a}"`).join(', ')}]`);
        if (node["client-fingerprint"]) lines.push(`    client-fingerprint: ${node["client-fingerprint"]}`);
    }

    if (node.reality) {
        lines.push(`    flow: ${node.flow || 'xtls-rprx-vision'}`);
        lines.push(`    reality-opts:`);
        lines.push(`      public-key: ${safeStr(node.reality.publicKey)}`);
        if (node.reality.shortId) lines.push(`      short-id: ${safeStr(node.reality.shortId)}`);
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
        if (node.network === 'grpc' && node['grpc-opts']) {
            lines.push(`    grpc-opts:`);
            lines.push(`      grpc-service-name: ${safeStr(node['grpc-opts']['grpc-service-name'])}`);
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
        lines.push(`    udp-relay-mode: native`);
        lines.push(`    congestion-controller: bbr`);
    }

    return lines.join('\n');
}

// --- 核心：解析器与生成器 ---
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
            if (node.cipher && node.password) {
                return `ss://${safeBase64Encode(`${node.cipher}:${node.password}`)}@${node.server}:${node.port}#${safe(node.name)}`;
            }
        }
        // 如果无法生成链接，返回空字符串，但保留节点对象以便前端调试（可选），这里遵循原逻辑返回空
        return node.link || '';
    } catch (e) { return ''; }
}

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
            node.link = generateNodeLink(node);
            nodes.push(node);
        }
    }
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        if (/^(proxies|Proxy):/i.test(line)) { inProxyBlock = true; continue; }
        if (/^(proxy-groups|rules|rule-providers):/i.test(line)) { inProxyBlock = false; break; }
        if (inProxyBlock && line.startsWith('-')) {
             if (line.includes('name:') && line.includes('server:')) { parseLineObj(line); } 
             else {
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
    
    // 1. YAML 检测
    if (decoded.includes('proxies:') || decoded.includes('Proxy:') || decoded.includes('- name:')) {
        const yamlNodes = parseYamlProxies(decoded);
        if (yamlNodes.length > 0) return yamlNodes;
    }

    // 2. 通用链接处理
    const splitText = decoded.replace(/(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//gi, '\n$1://');
    const lines = splitText.split(/[\r\n]+/);
    
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
                    servername: params.get('sni') || params.get('host'),
                    "skip-cert-verify": params.get('allowInsecure') === '1',
                    flow: params.get('flow'),
                    "client-fingerprint": params.get('fp')
                };
                
                // --- 修复 SS 逻辑 (针对复杂加密算法和URL编码) ---
                if (protocol === 'ss') {
                    // 1. 尝试直接从 username 获取 (ss://method:pass@...)
                    // Cloudflare 某些环境下 URL 解析可能不会自动解码所有字符，所以强制解码一次
                    let userStr = url.username;
                    try { userStr = decodeURIComponent(url.username); } catch(e) {}
                    
                    if (userStr.includes(':')) {
                        const parts = userStr.split(':');
                        node.cipher = parts[0];
                        node.password = parts.slice(1).join(':');
                    } else {
                        // 2. 尝试 Base64 解码 (SIP002: ss://base64(method:pass)@...)
                        try {
                            const decoded = safeBase64Decode(url.username); // 这里传入原始 username
                            if (decoded && decoded.includes(':')) {
                                const parts = decoded.split(':');
                                node.cipher = parts[0];
                                node.password = parts.slice(1).join(':');
                            }
                        } catch(e) {}
                    }
                    
                    // 3. 兼容旧格式 (ss://method:pass@...) 如果 URL 对象把密码解析到了 password 字段
                    if (!node.cipher && url.password) {
                        node.cipher = decodeURIComponent(url.username);
                        node.password = decodeURIComponent(url.password);
                    }
                }
                // ---------------------------------------------------
                
                if (node.network === 'ws') node['ws-opts'] = { path: params.get('path')||'/', headers: { Host: params.get('host')||node.servername } };
                if (params.get('security') === 'reality') { node.tls = true; node.reality = { publicKey: params.get('pbk'), shortId: params.get('sid') }; if(!node['client-fingerprint']) node['client-fingerprint']='chrome'; }
                if (protocol === 'hysteria2') { node.obfs = params.get('obfs'); node['obfs-password'] = params.get('obfs-password'); node.udp = true; }
                if (protocol === 'tuic') { node['congestion-controller'] = params.get('congestion_control'); node['udp-relay-mode'] = params.get('udp_relay_mode'); node.alpn = [params.get('alpn')||'h3']; node.udp = true; }
                if ((protocol === 'vless' || protocol === 'trojan') && node.network === 'ws') node.udp = true;

                nodes.push(node);
            }
        } catch(e) {}
    }
    
    return nodes.map(n => {
        if (!n.link) n.link = generateNodeLink(n);
        return n;
    });
}

// --- 路由 ---

// A. Clash 订阅
app.get('/subscribe/clash', async (c) => {
    try {
        const token = c.req.query('token')
        if (token !== c.env.ADMIN_PASSWORD) return c.text('Unauthorized', 401)
        
        const { results: subs } = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC").all()
        
        let template = "";
        try {
            const { results: tmpl } = await c.env.DB.prepare("SELECT content FROM templates WHERE is_default = 1 LIMIT 1").all()
            if (tmpl.length > 0) template = tmpl[0].content
        } catch(e) {}

        if (!template) {
            template = `port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: '0.0.0.0:9090'
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
  - MATCH,🚀 节点选择`;
        }

        let allNodes = []
        for (const sub of subs) {
            // 严格过滤：再次确认状态
            if (Number(sub.status) !== 1) continue;

            let content = "";
            if (sub.type === 'node') content = sub.url;
            else {
                const res = await fetchWithSmartUA(sub.url);
                if(res && res.ok) content = res.prefetchedText || await res.text();
            }
            
            const nodes = parseNodesCommon(content);
            let params = {}; try { params = sub.params ? JSON.parse(sub.params) : {} } catch(e) {}
            const allowed = params.include?.length ? new Set(params.include) : null;

            for(const node of nodes) {
                if (allowed && !allowed.has(node.name)) continue;
                // 确保 SS 节点有 cipher 和 password，否则 Clash 会报错
                if (node.type === 'ss' && (!node.cipher || !node.password)) continue;

                let name = node.name.trim();
                let i = 1;
                while (allNodes.some(n => n.name === name)) name = `${node.name} ${i++}`;
                node.name = name;
                allNodes.push(node);
            }
        }

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

// B. Base64 订阅
app.get('/subscribe/base64', async (c) => {
    try {
        const token = c.req.query('token')
        if (token !== c.env.ADMIN_PASSWORD) return c.text('Unauthorized', 401)
        const { results: subs } = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC").all()
        let links = [];
        for (const sub of subs) {
            // 严格过滤：再次确认状态
            if (Number(sub.status) !== 1) continue;

             let content = "";
            if (sub.type === 'node') content = sub.url;
            else { const res = await fetchWithSmartUA(sub.url); if(res && res.ok) content = res.prefetchedText || await res.text(); }
            const nodes = parseNodesCommon(content);
            let params = {}; try { params = sub.params ? JSON.parse(sub.params) : {} } catch(e) {}
            const allowed = params.include?.length ? new Set(params.include) : null;
            for (const node of nodes) {
                if (allowed && !allowed.has(node.name)) continue;
                links.push(generateNodeLink(node));
            }
        }
        return c.text(btoa(encodeURIComponent(links.join('\n')).replace(/%([0-9A-F]{2})/g, (m, p1) => String.fromCharCode('0x' + p1))))
    } catch(e) { return c.text(e.message, 500) }
})

// C. Check 接口
app.post('/check', async (c) => {
    const { url, type } = await c.req.json();
    try {
        let content = "";
        let stats = null;
        if (type === 'node') {
            content = url; 
        } else {
            const res = await fetchWithSmartUA(url);
            if(!res || !res.ok) throw new Error(`Connect Failed`);
            content = res.prefetchedText || await res.text();
            
            if(res.trafficInfo) {
                stats = res.trafficInfo;
            }
        }

        const rawNodes = parseNodesCommon(content);
        const nodes = rawNodes.map(n => ({ ...n, link: generateNodeLink(n) }));

        return c.json({ success: true, data: { valid: true, nodeCount: nodes.length, stats, nodes } });
    } catch(e) { return c.json({ success: false, error: e.message }) }
})

// CRUD
app.get('/subs', async (c) => { 
    const {results} = await c.env.DB.prepare("SELECT * FROM subscriptions ORDER BY sort_order ASC, id DESC").all(); 
    return c.json({success:true, data:results.map(i=>{
        try{i.info=JSON.parse(i.info);i.params=JSON.parse(i.params)}catch(e){}
        return i
    })}) 
})

app.post('/subs', async (c) => { 
    const b=await c.req.json(); 
    await c.env.DB.prepare("INSERT INTO subscriptions (name,url,type,params,info,sort_order,status) VALUES (?,?,?,?,?,0,1)")
    .bind(b.name,b.url,b.type||'sub',JSON.stringify(b.params||{}),'{}').run(); 
    return c.json({success:true}) 
})

// --- 修复 PUT：更安全的更新逻辑，防止 0 被忽略 ---
app.put('/subs/:id', async (c) => { 
    const b = await c.req.json(); 
    const id = c.req.param('id');
    
    // 构建 SQL
    let parts = ["updated_at=CURRENT_TIMESTAMP"];
    let args = [];
    
    if (b.name !== undefined) { parts.push("name=?"); args.push(b.name); }
    if (b.url !== undefined) { parts.push("url=?"); args.push(b.url); }
    if (b.type !== undefined) { parts.push("type=?"); args.push(b.type); }
    
    // 显式处理 status，确保 0 被正确更新
    if (b.status !== undefined) { parts.push("status=?"); args.push(parseInt(b.status)); }
    
    if (b.params) { parts.push("params=?"); args.push(JSON.stringify(b.params)); }
    if (b.info) { parts.push("info=?"); args.push(JSON.stringify(b.info)); }
    
    const query = `UPDATE subscriptions SET ${parts.join(', ')} WHERE id=?`;
    args.push(id);
    
    await c.env.DB.prepare(query).bind(...args).run(); 
    return c.json({success:true}) 
})

app.delete('/subs/:id', async (c) => { await c.env.DB.prepare("DELETE FROM subscriptions WHERE id=?").bind(c.req.param('id')).run(); return c.json({success:true}) })
app.post('/sort', async (c) => { const {ids}=await c.req.json(); const s=c.env.DB.prepare("UPDATE subscriptions SET sort_order=? WHERE id=?"); await c.env.DB.batch(ids.map((id,i)=>s.bind(i,id))); return c.json({success:true}) })
app.post('/backup/import', async (c) => { const {items}=await c.req.json(); const s=c.env.DB.prepare("INSERT INTO subscriptions (name, url, type, info, params, status, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)"); await c.env.DB.batch(items.map(i=>s.bind(i.name,i.url,i.type||'subscription',JSON.stringify(i.info),JSON.stringify(i.params),i.status??1,i.sort_order??0))); return c.json({success:true}) })
app.post('/login', async (c) => { const {password}=await c.req.json(); return c.json({success: password===c.env.ADMIN_PASSWORD}) })
app.get('/template/default', async (c) => { const {results}=await c.env.DB.prepare("SELECT content FROM templates WHERE is_default=1").all(); return c.json({success:true, data: results[0]?.content||""}) })
app.post('/template/default', async (c) => { const {content}=await c.req.json(); await c.env.DB.prepare("UPDATE templates SET content=? WHERE is_default=1").bind(content).run(); return c.json({success:true}) })
app.get('/settings', async(c)=>{return c.json({success:true,data:{}})}) 
app.post('/settings', async(c)=>{return c.json({success:true})})

export const onRequest = handle(app)
