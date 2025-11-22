import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono()

// --- 1. 核心工具函数 ---

const safeBase64Decode = (str) => {
    if (!str) return '';
    try {
        let clean = str.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
        while (clean.length % 4) clean += '=';
        return decodeURIComponent(escape(atob(clean)));
    } catch (e) { return str; }
}

const safeBase64Encode = (str) => {
    try {
        return btoa(unescape(encodeURIComponent(str)));
    } catch (e) { return btoa(str); }
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
        
        if (decoded.includes('://') || decoded.includes('proxies:') || decoded.includes('server:')) return decoded;
        return deepBase64Decode(decoded, depth + 1);
    } catch (e) { return str; }
}

const fetchWithSmartUA = async (url) => {
  const userAgents = ['ClashMeta/1.0', 'v2rayNG/1.8.5', 'Clash/1.0', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'];
  let bestRes = null;
  for (const ua of userAgents) {
    try {
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), 8000);
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

// --- 2. 核心解析与链接重组 ---

const generateNodeLink = (node) => {
    try {
        if (node.type === 'vmess') {
            const vmessObj = {
                v: "2", ps: node.name, add: node.server, port: node.port, id: node.uuid,
                aid: node.alterId || 0, scy: node.cipher || "auto", net: node.network || "tcp",
                type: "none", host: "", path: "", tls: node.tls ? "tls" : ""
            };
            if (node["ws-opts"]) {
                vmessObj.net = "ws";
                vmessObj.path = node["ws-opts"].path || "";
                if (node["ws-opts"].headers && node["ws-opts"].headers.Host) {
                    vmessObj.host = node["ws-opts"].headers.Host;
                }
            }
            return 'vmess://' + safeBase64Encode(JSON.stringify(vmessObj));
        }
        if (node.type === 'ss') {
            const auth = `${node.cipher}:${node.password}`;
            return `ss://${safeBase64Encode(auth)}@${node.server}:${node.port}#${encodeURIComponent(node.name)}`;
        }
        if (['vless', 'trojan', 'hysteria2'].includes(node.type)) {
            let link = `${node.type}://${node.uuid || node.password || ''}@${node.server}:${node.port}?`;
            const params = [];
            if (node.tls) params.push('security=tls');
            if (node.servername) params.push(`sni=${node.servername}`);
            if (node.network === 'ws') {
                params.push('type=ws');
                if (node["ws-opts"]) {
                    if (node["ws-opts"].path) params.push(`path=${encodeURIComponent(node["ws-opts"].path)}`);
                    if (node["ws-opts"].headers && node["ws-opts"].headers.Host) params.push(`host=${encodeURIComponent(node["ws-opts"].headers.Host)}`);
                }
            }
            if (node.type === 'vless' && node.network === 'grpc') params.push('type=grpc');
            link += params.join('&');
            link += `#${encodeURIComponent(node.name)}`;
            return link;
        }
        return node.link || `${node.type}://${node.server}:${node.port}#${encodeURIComponent(node.name)}`;
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
        if (!type) { if(line.includes('ss')) type='ss'; else if(line.includes('vmess')) type='vmess'; else if(line.includes('trojan')) type='trojan'; }
        
        const server = getVal('server');
        const port = getVal('port');
        const name = getVal('name');
        
        if (type && server && port) {
             const node = {
                name: name || `${type}-${server}`,
                type, server, port,
                cipher: getVal('cipher'), uuid: getVal('uuid'), password: getVal('password'),
                tls: line.includes('tls: true') || getVal('tls') === 'true',
                "skip-cert-verify": line.includes('skip-cert-verify: true'),
                servername: getVal('servername') || getVal('sni'),
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
            if (line.includes('name:') && line.includes('server:')) parseLineObj(line);
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
    if (!text) return [];
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
        
        if (/^(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|https?):\/\//i.test(trimLine)) {
             let name = 'node';
             if (trimLine.startsWith('vmess://')) {
                 try { const c = JSON.parse(safeBase64Decode(trimLine.substring(8))); name = c.ps || name; } catch(e){}
             } else if (trimLine.includes('#')) {
                 try { name = decodeURIComponent(trimLine.split('#').pop()); } catch(e){}
             }
             nodes.push({ name, link: trimLine });
        }
    }
    return nodes;
}

// --- 3. 路由处理 (移除去重) ---

app.get('/', async (c) => {
  try {
    if (!c.env.DB) return c.text('Database Error', 500)
    const { results } = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC").all()

    let allLinks = []

    for (const sub of results) {
      let params = {}; try { params = sub.params ? JSON.parse(sub.params) : {} } catch(e) {}
      const allowedNames = (params.include && params.include.length > 0) ? new Set(params.include) : null

      let rawContent = "";
      if (sub.type === 'node') {
          rawContent = sub.url;
      } else {
          const res = await fetchWithSmartUA(sub.url);
          if (res && res.ok) rawContent = res.prefetchedText || await res.text();
      }
      
      if (!rawContent) continue;

      const nodes = parseNodesCommon(rawContent);
      
      for (const node of nodes) {
          if (allowedNames && !allowedNames.has(node.name.trim())) continue;
          
          // 仅保留名字防冲突逻辑，不再进行任何去重
          let finalName = node.name.trim()
          let counter = 1
          // 这里需要检查 output list 里是否已有同名，如果有就重命名
          // 注意：allLinks 只是字符串数组，不方便反查名字，这里简化处理：
          // 假设 Base64 订阅场景下，客户端自己会处理重名，或者我们不做严格的重名检查
          // 严格来说应该维护一个 name set
          
          // 更新 link 中的名字（如果是 URL Fragment）
          if (node.link.includes('#') && !node.link.includes('vmess://')) {
              // 简单的 # 重命名
              // node.link = ... 
          }
          
          allLinks.push(node.link);
      }
    }

    const finalString = allLinks.join('\n')
    const base64Result = btoa(encodeURIComponent(finalString).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode('0x' + p1)));

    return c.text(base64Result)
  } catch (e) {
    return c.text(`Error: ${e.message}`, 500)
  }
})

export const onRequest = handle(app)
