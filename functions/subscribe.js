import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono()

// 辅助函数：Base64 解码
const safeAtob = (str) => {
  try {
    return atob(str.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''))
  } catch (e) {
    return ""
  }
}

// 辅助函数：Base64 编码
const safeBtoa = (str) => {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
      function(match, p1) {
          return String.fromCharCode('0x' + p1);
      }
  ));
}

app.get('/', async (c) => {
  try {
    if (!c.env.DB) return c.text('Database Error', 500)

    // 1. 从数据库获取所有“启用”的资源
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC"
    ).all()

    let allNodes = []

    // 2. 遍历资源，进行抓取或合并
    for (const sub of results) {
      if (sub.type === 'node') {
        // 如果是单节点，直接加入
        allNodes.push(sub.url.trim())
      } else {
        // 如果是订阅链接，需要去下载内容
        try {
          const response = await fetch(sub.url, {
            headers: { 'User-Agent': 'v2rayNG/1.8.5' }
          })
          if (response.ok) {
            const text = await response.text()
            // 尝试 Base64 解码
            const decoded = safeAtob(text)
            if (decoded) {
              // 按行分割，加入总列表
              const lines = decoded.split(/\r?\n/).filter(line => line.trim() !== '')
              allNodes = allNodes.concat(lines)
            }
          }
        } catch (err) {
          console.error(`Fetching ${sub.name} failed:`, err)
          // 抓取失败跳过，不影响其他节点
        }
      }
    }

    // 3. 再次 Base64 编码输出 (v2ray 标准格式)
    const finalString = allNodes.join('\n')
    const base64Result = safeBtoa(finalString)

    return c.text(base64Result)

  } catch (e) {
    return c.text(`Error: ${e.message}`, 500)
  }
})

export const onRequest = handle(app)
