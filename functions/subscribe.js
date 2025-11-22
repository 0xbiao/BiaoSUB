import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono()

// --- 1. 核心工具函数 (与 API 保持一致) ---

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
        const binary = atob(safeStr);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        const decoded = new TextDecoder('utf-8').decode(bytes);
        
        if (decoded.includes('://') || decoded.includes('proxies:') || decoded.includes('server:')) return decoded;
        return deepBase64Decode(decoded, depth + 1);
    } catch (e) { return str; }
}

// 智能抓取：防止被机场拦截
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
        if (text.includes('<!DOCTYPE html>') || text.includes('<html')) continue; // 跳过网页干扰
        
        Object.defineProperty(res, 'prefetchedText', { value: text, writable: true });
        return res;
      }
    } catch (e) {}
  }
  return bestRes;
}

// --- 2. 核心解析逻辑 ---

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
             const node = { name: name || `${type}-${server}`, type, server, port, link: '' };
             node.link = `${type}://${server}:${port}#${encodeURIComponent(node.name)}`;
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

    // 1. YAML 解析
    if (decoded.includes('proxies:') || decoded.includes('Proxy:') || decoded.includes('- name:')) {
        const yamlNodes = parseYamlProxies(decoded);
        if (yamlNodes.length > 0) return yamlNodes;
    }

    // 2. 通用链接解析
    const splitText = decoded.replace(/(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|http|https):\/\//gi, '\n$1://');
    const lines = splitText.split(/\r?\n/);
    
    for (const line of lines) {
        const trimLine = line.trim();
        if (!trimLine || trimLine.length < 10) continue;
        
        // 简单链接提取
        if (/^(vmess|vless|ss|ssr|trojan|hysteria|hysteria2|tuic|juicity|naive|https?):\/\//i.test(trimLine)) {
             // 尝试提取名字用于白名单匹配
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

// --- 3. 路由处理 ---

app.get('/', async (c) => {
  try {
    if (!c.env.DB) return c.text('Database Error', 500)
    const { results } = await c.env.DB.prepare("SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC").all()

    let uniqueLinks = new Set()
    let orderedLinks = []

    for (const sub of results) {
      // 获取白名单
      let params = {}; try { params = sub.params ? JSON.parse(sub.params) : {} } catch(e) {}
      const allowedNames = (params.include && params.include.length > 0) ? new Set(params.include) : null

      // 获取原始内容
      let rawContent = "";
      if (sub.type === 'node') {
          rawContent = sub.url;
      } else {
          const res = await fetchWithSmartUA(sub.url);
          if (res && res.ok) rawContent = res.prefetchedText || await res.text();
      }
      
      if (!rawContent) continue;

      // 使用增强解析器
      const nodes = parseNodesCommon(rawContent);
      
      for (const node of nodes) {
          // 白名单过滤
          if (allowedNames && !allowedNames.has(node.name.trim())) continue;
          
          if (!uniqueLinks.has(node.link)) {
              uniqueLinks.add(node.link);
              orderedLinks.push(node.link);
          }
      }
    }

    // Base64 输出
    const finalString = orderedLinks.join('\n')
    const base64Result = btoa(encodeURIComponent(finalString).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode('0x' + p1)));

    return c.text(base64Result)
  } catch (e) {
    return c.text(`Error: ${e.message}`, 500)
  }
})

export const onRequest = handle(app)
