import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono()

// --- 辅助函数 ---
const safeAtob = (str) => {
  try {
    return atob(str.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''))
  } catch (e) {
    return ""
  }
}

const safeBtoa = (str) => {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
      function(match, p1) {
          return String.fromCharCode('0x' + p1);
      }
  ));
}

// 节点处理与清洗函数
const processNode = (link, globalExclude, localExclude, renameRules) => {
  const trimLink = link.trim()
  if (!trimLink) return null

  // 1. 提取节点名称 (用于过滤和重命名)
  let nodeName = ''
  let protocol = ''
  let isVmess = trimLink.startsWith('vmess://')
  let vmessConfig = null

  if (isVmess) {
    protocol = 'vmess'
    try {
      vmessConfig = JSON.parse(safeAtob(trimLink.substring(8)))
      nodeName = vmessConfig.ps || ''
    } catch (e) { return null } // 解析失败丢弃
  } else {
    // 处理 vless, trojan, ss 等
    const match = trimLink.match(/^(.*?):\/\//)
    if (!match) return null // 无法识别协议
    protocol = match[1]
    const hashIndex = trimLink.lastIndexOf('#')
    if (hashIndex !== -1) {
      try {
        nodeName = decodeURIComponent(trimLink.substring(hashIndex + 1))
      } catch (e) {
        nodeName = trimLink.substring(hashIndex + 1)
      }
    }
  }

  // 2. 执行过滤 (排除)
  // 2.1 全局排除
  if (globalExclude) {
    const globalRegex = new RegExp(globalExclude, 'i')
    if (globalRegex.test(nodeName)) return null
  }
  // 2.2 独立排除
  if (localExclude) {
    try {
      const localRegex = new RegExp(localExclude, 'i')
      if (localRegex.test(nodeName)) return null
    } catch(e) {}
  }

  // 3. 执行重命名
  let newName = nodeName
  if (renameRules && Array.isArray(renameRules)) {
    for (const rule of renameRules) {
      if (rule.src && rule.dst !== undefined) {
        try {
          // 支持简单的字符串替换或正则
          // 假设用户输入的是正则字符串，如果报错则回退到普通字符串替换
          const regex = new RegExp(rule.src, 'g')
          newName = newName.replace(regex, rule.dst)
        } catch (e) {
          newName = newName.split(rule.src).join(rule.dst)
        }
      }
    }
  }

  // 4. 重组链接
  if (newName !== nodeName) {
    if (isVmess) {
      vmessConfig.ps = newName
      return 'vmess://' + safeBtoa(JSON.stringify(vmessConfig))
    } else {
      // 对于非vmess，替换 #后面的部分
      const hashIndex = trimLink.lastIndexOf('#')
      if (hashIndex !== -1) {
        return trimLink.substring(0, hashIndex) + '#' + encodeURIComponent(newName)
      } else {
        return trimLink + '#' + encodeURIComponent(newName)
      }
    }
  }

  return trimLink
}


app.get('/', async (c) => {
  try {
    if (!c.env.DB) return c.text('Database Error', 500)

    // 1. 获取全局设置
    let globalExclude = ''
    try {
      const settingRes = await c.env.DB.prepare("SELECT value FROM settings WHERE key = 'global_exclude'").first()
      if (settingRes) globalExclude = settingRes.value
    } catch(e) {}

    // 2. 获取所有启用资源
    const { results } = await c.env.DB.prepare(
      "SELECT * FROM subscriptions WHERE status = 1 ORDER BY sort_order ASC, id DESC"
    ).all()

    let allNodes = []

    // 3. 遍历资源，抓取 -> 清洗 -> 合并
    for (const sub of results) {
      let rawNodes = []
      let params = {}
      
      try {
        params = sub.params ? JSON.parse(sub.params) : {}
      } catch(e) {}

      if (sub.type === 'node') {
        rawNodes.push(sub.url.trim())
      } else {
        try {
          const response = await fetch(sub.url, {
            headers: { 'User-Agent': 'v2rayNG/1.8.5' }
          })
          if (response.ok) {
            const text = await response.text()
            const decoded = safeAtob(text)
            if (decoded) {
              rawNodes = decoded.split(/\r?\n/).filter(line => line.trim() !== '')
            }
          }
        } catch (err) {
          console.error(`Fetching ${sub.name} failed:`, err)
        }
      }

      // 对当前订阅的节点进行清洗
      for (const link of rawNodes) {
        const processed = processNode(link, globalExclude, params.exclude, params.rename)
        if (processed) {
          allNodes.push(processed)
        }
      }
    }

    // 4. 输出结果
    const finalString = allNodes.join('\n')
    const base64Result = safeBtoa(finalString)

    return c.text(base64Result)

  } catch (e) {
    return c.text(`Error: ${e.message}`, 500)
  }
})

export const onRequest = handle(app)
