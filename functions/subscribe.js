import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono()

// --- 1. 工具 ---
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
        if (clean.includes('proxies:') || clean.includes('mixed-port:')) return str;
        let safeStr = clean.replace(/-/g, '+').replace(/_/g, '/');
        while (safeStr.length % 4) safeStr += '=';
        const decoded = new TextDecoder('utf-8').decode(Uint8Array.from(atob(safeStr), c => c.charCodeAt(0)));
        if (decoded.includes('://') || decoded.includes('proxies:')) return deepBase64Decode(decoded, depth + 1);
        return decoded;
    } catch (e) { return str; }
}

// --- 2. 智能 Fetch ---
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
        Object.defineProperty(res, 'prefetchedText', { value: text, writable: true });
        return res;
      }
    } catch (e) {}
  }
  return bestRes;
}

// --- 3. 生成标准链接 ---
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
        return node.link || '';
    } catch (e) { return ''; }
}

// --- 4. 解析器 ---
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
    if (decoded.includes('proxies:') || decoded.includes('Proxy:') || decoded.includes('- name:')) {
        const yamlNodes = parseYamlProxies(decoded);
        if (yamlNodes.length > 0) return yamlNodes;
    }
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
                
                // 修复 SS
                if (protocol === 'ss') {
                    let userStr = url.username;
                    try { userStr = decodeURIComponent(url.username); } catch(e) {}
                    if (userStr.includes(':')) {
                        const parts = userStr.split(':');
                        node.cipher = parts[0];
                        node.password = parts.slice(1).join(':');
                    } else {
                        try {
                            const decoded = safeBase64Decode(url.username);
                            if (decoded && decoded.includes(':')) {
                                const parts = decoded.split(':');
                                node.cipher = parts[0];
                                node.password = parts.slice(1).join(':');
                            }
                        } catch(e) {}
                    }
                    if (!node.cipher && url.password) {
                        node.cipher = decodeURIComponent(url.username);
                        node.password = decodeURIComponent(url.password);
                    }
                }
                
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

// --- 5. 主入口 ---
app.get('/', async (c) => {
    try {
        if (!c.env.DB) return c.text('Database Error', 500)
        const { results } = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC").all()
        let allLinks = []
        for (const sub of results) {
            // 严格过滤：再次确认状态
            if (Number(sub.status) !== 1) continue;

            let rawContent = "";
            if (sub.type === 'node') {
                rawContent = sub.url;
            } else {
                const res = await fetchWithSmartUA(sub.url);
                if (res && res.ok) rawContent = res.prefetchedText || await res.text();
            }
            if (!rawContent) continue;
            const nodes = parseNodesCommon(rawContent);
            let params = {}; try { params = sub.params ? JSON.parse(sub.params) : {} } catch(e) {}
            const allowed = params.include?.length ? new Set(params.include) : null;
            for (const node of nodes) {
                if (allowed && !allowed.has(node.name.trim())) continue;
                allLinks.push(generateNodeLink(node));
            }
        }
        return c.text(btoa(encodeURIComponent(allLinks.join('\n')).replace(/%([0-9A-F]{2})/g, (m, p1) => String.fromCharCode('0x' + p1))))
    } catch(e) { return c.text(e.message, 500) }
})

export const onRequest = handle(app)
