import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono()

// --- 辅助函数 ---
const safeAtob = (str) => {
  try {
    const clean = str.replace(/\s/g, '')
    const base64 = clean.replace(/-/g, '+').replace(/_/g, '/')
    return atob(base64)
  } catch (e) { return null }
}

const safeBtoa = (str) => {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
      function(match, p1) { return String.fromCharCode('0x' + p1); }
  ));
}

// 带重试机制的 Fetch
const fetchWithRetry = async (url, options = {}, retries = 2) => {
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await fetch(url, options)
      if (res.ok) return res
      // 如果是 404 或 401 这种明确的错误，就不重试了
      if (res.status === 404 || res.status === 401) return res
    } catch (err) {
      if (i === retries) throw err
    }
  }
}

const parseNodeName = (link) => {
  const trimLink = link.trim()
  if (!trimLink) return null
  if (trimLink.startsWith('vmess://')) {
    try {
      const config = JSON.parse(safeAtob(trimLink.substring(8)))
      return config.ps || ''
    } catch (e) { return '' }
  } 
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

    // 使用 Set 来存储节点，自动去重
    let uniqueNodes = new Set()
    // 保持顺序的数组
    let orderedNodes = []

    for (const sub of results) {
      let params = {}
      try { params = sub.params ? JSON.parse(sub.params) : {} } catch(e) {}
      
      // 1. 获取白名单和自定义 UA
      let allowedNodes = null
      if (params.include && Array.isArray(params.include) && params.include.length > 0) {
        allowedNodes = new Set(params.include)
      }
      
      const userAgent = params.ua || 'v2rayNG/1.8.5' // 优先使用自定义UA

      let rawContent = ""

      // 2. 获取内容
      if (sub.type === 'node') {
        rawContent = sub.url
      } else {
        try {
          const response = await fetchWithRetry(sub.url, { headers: { 'User-Agent': userAgent } })
          if (response && response.ok) {
            rawContent = await response.text()
          }
        } catch (err) {
          console.error(`Fetching ${sub.name} failed:`, err)
        }
      }

      if (!rawContent) continue

      // 3. 解析与筛选
      const decoded = safeAtob(rawContent)
      const contentToSplit = decoded !== null ? decoded : rawContent
      const lines = contentToSplit.split(/\r?\n/).filter(line => line.trim() !== '')
      
      for (const line of lines) {
        const link = line.trim()
        if (!link) continue

        // 筛选逻辑
        let keep = true
        if (allowedNodes) {
            const name = parseNodeName(link)
            if (!name || !allowedNodes.has(name)) {
                keep = false
            }
        }

        // 去重并添加
        if (keep) {
            if (!uniqueNodes.has(link)) {
                uniqueNodes.add(link)
                orderedNodes.push(link)
            }
        }
      }
    }

    const finalString = orderedNodes.join('\n')
    const base64Result = safeBtoa(finalString)

    return c.text(base64Result)

  } catch (e) {
    return c.text(`Error: ${e.message}`, 500)
  }
})

export const onRequest = handle(app)
