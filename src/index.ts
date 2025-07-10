import { Hono } from 'hono'
import { cors } from 'hono/cors'

import signup from './apis/auth/singup'
import login from './apis/auth/login'
import googleAuth from './apis/auth/googleAuth'
import me from './apis/auth/me'
import forgotPassword from './apis/auth/forgotPassword'
import logout from './apis/auth/logout'
import admin from './apis/auth/admin'
import payments from './apis/payments/payments'
import subscriptions from './apis/subscription/subscription'

export type Env = { 
  DB: D1Database
  GOOGLE_CLIENT_ID: string
  GOOGLE_CLIENT_SECRET: string
  SMTP_USER: string
  API_KEY: string
}

const app = new Hono<{ Bindings: Env }>()

// 👇 Allow CORS from anywhere
app.use('*', cors({
  origin: '*', // Allow all origins
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}))

// Auth routes
app.route('/api/auth/signup', signup)
app.route('/api/auth/login', login)
app.route('/api/auth/google', googleAuth)
app.route('/api/auth/me', me)
app.route('/api/auth/forgot-password', forgotPassword)
app.route('/api/auth/logout', logout)
app.route('/api/auth/admin', admin)

// Other routes
app.route('/api/payments', payments)
app.route('/api/subscriptions', subscriptions)

app.get('/', (c) => {
  return c.text('Hello this is a free api services!')
})

export default app
