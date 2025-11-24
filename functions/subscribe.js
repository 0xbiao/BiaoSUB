import { Hono } from 'hono'
import { handle } from 'hono/cloudflare-pages'

const app = new Hono()

const safeBase64Encode = (str) => { try { return btoa(unescape(encodeURIComponent(str))); } catch (e) { return btoa(str); } }

app.get('/', async (c) => {
    // 这里只保留一个简单入口，核心逻辑都由 API 处理
    return c.text('BiaoSUB Worker is running.')
})

export const onRequest = handle(app)
