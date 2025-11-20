import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono()

// --- 辅助函数：Base64 安全解码 ---
const safeAtob = (str) => {
  try {
    const clean = str.replace(/\s/g, '')
    const base64 = clean.replace(/-/g, '+').replace(/_/g, '/')
    return atob(base64)
  } catch (e) {
    return null
  }
}

// --- 辅助函数：Base64 安全编码 ---
const safeBtoa = (str) => {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
      function(match, p1) {
          return String.fromCharCode('0x' + p1);
      }
  ));
}

// --- 辅助函数：带重试机制的 Fetch ---
const fetchWithRetry = async (url, options = {}, retries = 2) => {
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await fetch(url, options)
      // 如果请求成功，直接返回
      if (res.ok) return res
      // 如果是 404 或 401 这种明确的客户端错误，通常重试也没用，直接返回
      if (res.status === 404 || res.status === 401) return res
      // 其他错误（如 500, 502, 503）抛出异常触发重试
      if (i === retries) return res
    } catch (err) {
      if (i === retries) throw err
    }
  }
}

// --- 辅助函数：解析节点名称 (用于白名单比对) ---
const parseNodeName = (link) => {
  const trimLink = link.trim()
  if (!trimLink) return null

  // 1. 处理 vmess
  if (trimLink.startsWith('vmess://')) {
    try {
      const b64 = trimLink.substring(8).replace(/-/g, '+').replace(/_/g, '/')
      const config = JSON.parse(atob(b64))
      return config.ps || ''
    } catch (e) { return '' }
  } 
  
  // 2. 处理其他协议 (vless, hysteria2, trojan 等)
  // 格式通常是 protocol://...#备注
  const hashIndex = trimLink.lastIndexOf('#')
  if (hashIndex !== -1) {
    try {
      return decodeURIComponent(trimLink.substring(hashIndex + 1))
    } catch (e) {
      return trimLink.substring(hashIndex + 1)
    }
  }
  return ''
}

app.get('/', async (c) => {
  try {
    if (!c.env.DB) return c.text('Database Error', 500)

    // 1. 获取所有启用的订阅源
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC"
    ).all()

    // 使用 Set 来存储节点链接，自动去重
    let uniqueNodes = new Set()
    // 使用 Array 来保持顺序
    let orderedNodes = []

    for (const sub of results) {
      // 解析 params
      let params = {}
      try {
        params = sub.params ? JSON.parse(sub.params) : {}
      } catch(e) {}
      
      // 获取白名单设置
      let allowedNodes = null
      if (params.include && Array.isArray(params.include) && params.include.length > 0) {
        allowedNodes = new Set(params.include)
      }
      
      // 获取自定义 User-Agent，默认使用 v2rayNG
      const userAgent = params.ua || 'v2rayNG/1.8.5'

      let rawContent = ""

      // 2. 获取原始内容
      if (sub.type === 'node') {
        // 自建节点：内容直接在 url 字段里
        rawContent = sub.url
      } else {
        // 订阅链接：需要下载
        try {
          const response = await fetchWithRetry(sub.url, { 
            headers: { 'User-Agent': userAgent } 
          })
          if (response && response.ok) {
            rawContent = await response.text()
          }
        } catch (err) {
          console.error(`Fetching ${sub.name} failed:`, err)
          // 抓取失败则跳过该订阅
        }
      }

      if (!rawContent) continue

      // 3. 解析内容 (处理 Base64 编码的情况)
      const decoded = safeAtob(rawContent)
      // 如果解码成功，说明原内容是 Base64；如果失败(返回null)，说明原内容可能是明文列表
      const contentToSplit = decoded !== null ? decoded : rawContent
      
      // 按行分割
      const lines = contentToSplit.split(/\r?\n/).filter(line => line.trim() !== '')
      
      // 4. 遍历每一行(每一个节点)进行筛选和去重
      for (const line of lines) {
        const link = line.trim()
        if (!link) continue

        // --- 筛选逻辑 ---
        let keep = true
        if (allowedNodes) {
            const name = parseNodeName(link)
            // 如果解析不出名字，或者名字不在白名单里，则丢弃
            if (!name || !allowedNodes.has(name)) {
                keep = false
            }
        }

        // --- 去重与添加 ---
        if (keep) {
            if (!uniqueNodes.has(link)) {
                uniqueNodes.add(link)
                orderedNodes.push(link)
            }
        }
      }
    }

    // 5. 重新打包输出
    const finalString = orderedNodes.join('\n')
    const base64Result = safeBtoa(finalString)

    return c.text(base64Result)

  } catch (e) {
    return c.text(`Error: ${e.message}`, 500)
  }
})

export const onRequest = handle(app)
