import { Hono } from 'hono'
import signup from './apis/auth/singup'
import login from './apis/auth/login'
import googleAuth from './apis/auth/googleAuth'

export type Env = { 
  DB: D1Database
}

const app = new Hono<{ Bindings: Env }>()

app.route('/api/auth/signup', signup)
app.route('/api/auth/login', login)
app.route('/api/auth/google', googleAuth)

app.get('/', (c) => {
  return c.text('Hello Hono!')
})

export default app
