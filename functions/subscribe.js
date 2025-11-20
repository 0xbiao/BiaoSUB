import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono()

// 安全的 Base64 解码，失败返回 null
const safeAtob = (str) => {
  try {
    // 移除空白字符
    const clean = str.replace(/\s/g, '')
    // 处理 URL safe 字符
    const base64 = clean.replace(/-/g, '+').replace(/_/g, '/')
    return atob(base64)
  } catch (e) {
    return null
  }
}

const safeBtoa = (str) => {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
      function(match, p1) { return String.fromCharCode('0x' + p1); }
  ));
}

// 解析单个节点并提取名称 (用于比对白名单)
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
    try { return decodeURIComponent(trimLink.substring(hashIndex + 1)) } catch (e) { return trimLink.substring(hashIndex + 1) }
  }
  return ''
}

app.get('/', async (c) => {
  try {
    if (!c.env.DB) return c.text('Database Error', 500)

    const { results } = await c.env.DB.prepare(
      "SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC"
    ).all()

    let allNodes = []

    for (const sub of results) {
      // 1. 获取自选白名单
      let allowedNodes = null
      try {
        const params = sub.params ? JSON.parse(sub.params) : {}
        if (params.include && Array.isArray(params.include) && params.include.length > 0) {
          allowedNodes = new Set(params.include)
        }
      } catch(e) {}

      let rawContent = ""

      // 2. 获取原始内容 (无论是 URL 下载的还是直接填写的)
      if (sub.type === 'node') {
        rawContent = sub.url
      } else {
        try {
          const response = await fetch(sub.url, { headers: { 'User-Agent': 'v2rayNG/1.8.5' } })
          if (response.ok) {
            rawContent = await response.text()
          }
        } catch (err) {
          console.error(`Fetching ${sub.name} failed:`, err)
        }
      }

      if (!rawContent) continue

      // 3. 解析内容为行列表
      // 尝试 Base64 解码，如果失败(返回null)则认为原文就是明文列表
      const decoded = safeAtob(rawContent)
      const contentToSplit = decoded !== null ? decoded : rawContent
      
      const lines = contentToSplit.split(/\r?\n/).filter(line => line.trim() !== '')
      
      // 4. 遍历每一行(每一个节点)进行筛选
      for (const line of lines) {
        const link = line.trim()
        if (!link) continue

        if (allowedNodes) {
            // 如果启用了白名单，提取名字进行比对
            const name = parseNodeName(link)
            // 如果名字存在且在白名单里，或者是白名单里的原始链接(防止重名匹配错误)，则保留
            if (name && allowedNodes.has(name)) {
                allNodes.push(link)
            }
        } else {
            // 没有白名单，全部保留
            allNodes.push(link)
        }
      }
    }

    const finalString = allNodes.join('\n')
    const base64Result = safeBtoa(finalString)

    return c.text(base64Result)

  } catch (e) {
    return c.text(`Error: ${e.message}`, 500)
  }
})

export const onRequest = handle(app)
