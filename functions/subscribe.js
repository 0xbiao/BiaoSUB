import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono()

// --- 辅助函数 ---
const safeAtob = (str) => {
  try {
    const clean = str.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/')
    return atob(clean)
  } catch (e) { return null }
}

const safeBtoa = (str) => {
  try {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode('0x' + p1)))
  } catch (e) { return str }
}

const fetchWithRetry = async (url, options = {}, retries = 1) => {
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await fetch(url, options)
      if (res.ok || res.status === 404 || res.status === 401) return res
    } catch (err) { if (i === retries) throw err }
  }
}

// --- 核心：增强版节点名称解析 ---
const parseNodeName = (link) => {
  const trimLink = link.trim()
  if (!trimLink) return null

  let name = ''
  // 1. VMess (JSON Base64)
  if (trimLink.startsWith('vmess://')) {
    try {
      const b64 = trimLink.substring(8).replace(/-/g, '+').replace(/_/g, '/')
      const config = JSON.parse(atob(b64))
      name = config.ps
    } catch (e) {}
  } 
  // 2. VLESS / Trojan / Hysteria 等 (URL Fragment)
  else if (trimLink.includes('#')) {
    const hashIndex = trimLink.lastIndexOf('#')
    const rawName = trimLink.substring(hashIndex + 1)
    try { name = decodeURIComponent(rawName) } catch (e) { name = rawName }
  }

  // 统一清理名称中的特殊空白，提高匹配率
  return name ? name.trim() : null
}

app.get('/', async (c) => {
  try {
    if (!c.env.DB) return c.text('Database Error: Please bind D1', 500)

    // 获取所有启用的订阅
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC"
    ).all()

    let uniqueNodes = new Set()
    let orderedNodes = []

    for (const sub of results) {
      // 1. 解析白名单参数
      let allowedNodes = null
      let params = {}
      try { params = sub.params ? JSON.parse(sub.params) : {} } catch(e) {}
      
      if (params.include && Array.isArray(params.include) && params.include.length > 0) {
        // 创建白名单 Set，存入时也做 trim 处理，防止因为空格导致不匹配
        allowedNodes = new Set(params.include.map(n => n.trim()))
      }

      // 2. 获取内容
      let rawContent = ""
      if (sub.type === 'node') {
        rawContent = sub.url
      } else {
        try {
          const ua = params.ua || 'v2rayNG/1.8.5'
          const response = await fetchWithRetry(sub.url, { headers: { 'User-Agent': ua } })
          if (response && response.ok) rawContent = await response.text()
        } catch (err) {}
      }

      if (!rawContent) continue

      // 3. 解码与分割
      const decoded = safeAtob(rawContent)
      const contentToSplit = decoded !== null ? decoded : rawContent
      const lines = contentToSplit.split(/\r?\n/).filter(line => line.trim() !== '')

      // 4. 筛选逻辑
      for (const line of lines) {
        const link = line.trim()
        // 跳过非链接行 (简单的正则判断，防止保留了注释或空行)
        if (!link.includes('://')) continue

        let keep = true
        
        // 如果设置了白名单（include），则进行名称比对
        if (allowedNodes) {
            const extractedName = parseNodeName(link)
            // 如果解析不出名字，或者名字不在白名单内，则过滤
            if (!extractedName || !allowedNodes.has(extractedName)) {
                keep = false
            }
        }

        if (keep) {
            if (!uniqueNodes.has(link)) {
                uniqueNodes.add(link)
                orderedNodes.push(link)
            }
        }
      }
    }

    // 5. 输出结果 (Base64)
    const finalString = orderedNodes.join('\n')
    const base64Result = safeBtoa(finalString)

    return c.text(base64Result)

  } catch (e) {
    return c.text(`Error: ${e.message}`, 500)
  }
})

export const onRequest = handle(app)
