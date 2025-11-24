import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono()

// --- 1. 工具函数 ---
const safeBase64Encode = (str) => { try { return btoa(unescape(encodeURIComponent(str))); } catch (e) { return btoa(str); } }
const safeBase64Decode = (str) => {
    if (!str) return '';
    try {
        let clean = str.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
        while (clean.length % 4) clean += '=';
        return decodeURIComponent(escape(atob(clean)));
    } catch (e) { return str; }
}
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

// --- 2. 核心：生成标准链接 (同步 API 逻辑) ---
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

// --- 3. 解析器 (同步 API 逻辑) ---
const parseNodesCommon = (text) => {
    let nodes = [];
    let decoded = deepBase64Decode(text);
    
    const yamlMatch = decoded.match(/proxies:\s*([\s\S]*?)(?:proxy-groups:|rules:|$)/);
    if (yamlMatch) {
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
                     try { const d = safeBase64Decode(url.username); if (d.includes(':')) { const [m, p] = d.split(':'); node.cipher = m; node.password = p; } else { node.cipher = url.username; node.password = url.password; } } catch(e){}
                }
                if (node.network === 'ws') node['ws-opts'] = { path: params.get('path'), headers: { Host: params.get('host') } };
                if (params.get('security') === 'reality') { node.tls = true; node.reality = { publicKey: params.get('pbk'), shortId: params.get('sid') }; }
                if (protocol === 'hysteria2') { node.obfs = params.get('obfs'); node['obfs-password'] = params.get('obfs-password'); node.udp = true; }
                if (protocol === 'tuic') { node.alpn = [params.get('alpn')||'h3']; node.udp = true; }
                nodes.push(node);
            }
        } catch(e) {}
    }
    
    return nodes.map(n => {
        if (!n.link) n.link = generateNodeLink(n);
        return n;
    });
}

app.get('/', async (c) => {
    try {
        if (!c.env.DB) return c.text('Database Error', 500)
        const { results } = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC").all()
        let allLinks = []
        for (const sub of results) {
            let content = "";
            if (sub.type === 'node') content = sub.url;
            else {
                try {
                    const ua = 'ClashMeta/1.0';
                    const res = await fetch(sub.url, { headers: { 'User-Agent': ua } });
                    if(res.ok) content = await res.text();
                } catch(e){}
            }
            const nodes = parseNodesCommon(content);
            let params = {}; try { params = JSON.parse(sub.params) } catch(e) {}
            const allowed = params.include?.length ? new Set(params.include) : null;
            for (const node of nodes) {
                if (allowed && !allowed.has(node.name)) continue;
                allLinks.push(node.link);
            }
        }
        return c.text(btoa(encodeURIComponent(allLinks.join('\n')).replace(/%([0-9A-F]{2})/g, (m, p1) => String.fromCharCode('0x' + p1))))
    } catch(e) { return c.text(e.message, 500) }
})

export const onRequest = handle(app)
