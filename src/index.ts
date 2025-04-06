import { Hono } from 'hono'
import { cors } from 'hono/cors'

import signup from './apis/auth/singup'
import login from './apis/auth/login'
import googleAuth from './apis/auth/googleAuth'
import payments from './apis/payments/payments'
import subscriptions from './apis/subscription/subscription'

export type Env = { 
  DB: D1Database
}

const app = new Hono<{ Bindings: Env }>()

// 👇 Allow CORS from anywhere
app.use('*', cors({
  origin: '*', // Allow all origins
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
}))

app.route('/api/auth/signup', signup)
app.route('/api/auth/login', login)
app.route('/api/auth/google', googleAuth)
app.route('/api/payments', payments)
app.route('/api/subscription', subscriptions)

app.get('/', (c) => {
  return c.text('Hello Hono!')
})

export default app
