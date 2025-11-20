import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono()

const safeAtob = (str) => {
  try { return atob(str.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '')) } catch (e) { return "" }
}

const safeBtoa = (str) => {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
      function(match, p1) { return String.fromCharCode('0x' + p1); }
  ));
}

// 解析单个节点并提取名称
const parseNodeName = (link) => {
  const trimLink = link.trim()
  if (!trimLink) return null
  
  if (trimLink.startsWith('vmess://')) {
    try {
      const config = JSON.parse(safeAtob(trimLink.substring(8)))
      return config.ps || ''
    } catch (e) { return '' }
  } else {
    const hashIndex = trimLink.lastIndexOf('#')
    if (hashIndex !== -1) {
      try { return decodeURIComponent(trimLink.substring(hashIndex + 1)) } catch (e) { return trimLink.substring(hashIndex + 1) }
    }
    return ''
  }
}

app.get('/', async (c) => {
  try {
    if (!c.env.DB) return c.text('Database Error', 500)

    const { results } = await c.env.DB.prepare(
      "SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC"
    ).all()

    let allNodes = []

    for (const sub of results) {
      // 1. 获取当前订阅的“自选白名单”
      let allowedNodes = null
      try {
        const params = sub.params ? JSON.parse(sub.params) : {}
        if (params.include && Array.isArray(params.include) && params.include.length > 0) {
          allowedNodes = new Set(params.include)
        }
      } catch(e) {}

      let currentSubNodes = []

      // 2. 获取节点
      if (sub.type === 'node') {
        currentSubNodes.push(sub.url.trim())
      } else {
        try {
          const response = await fetch(sub.url, { headers: { 'User-Agent': 'v2rayNG/1.8.5' } })
          if (response.ok) {
            const text = await response.text()
            const decoded = safeAtob(text)
            if (decoded) {
              currentSubNodes = decoded.split(/\r?\n/).filter(line => line.trim() !== '')
            }
          }
        } catch (err) {
          console.error(`Fetching ${sub.name} failed:`, err)
        }
      }

      // 3. 筛选逻辑：如果有白名单，只保留名单内的节点
      for (const link of currentSubNodes) {
        if (allowedNodes) {
            const name = parseNodeName(link)
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
