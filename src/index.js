import cookieParser from 'cookie-parser'
import express from 'express'
import jwt from 'jsonwebtoken'

import { JWT_SECRET_KEY, PORT } from './config.js'
import { UserRepository } from './user-repository.js'
import { isProduction } from './utils.js'

const app = express()

app.set('view engine', 'ejs')

app.use(express.json())
app.use(cookieParser())

app.use((req, res, next) => {
  const token = req.cookies.access_token

  try {
    const data = jwt.verify(token, JWT_SECRET_KEY)
    req.session = { user: data }
  } catch {}

  next()
})

app.get('/', (req, res) => {
  res.render('index', req.session?.user)
})

app.get('/protected', (req, res) => {
  if (!req.session?.user) {
    return res.status(403).send('Access not authorized')
  }

  res.render('protected', req.session.user)
})

app.post('/register', async (req, res) => {
  const { username, password } = req.body

  try {
    const id = await UserRepository.create({ username, password })
    res.status(201).send({ id })
  } catch (error) {
    res.status(400).send(error.message)
  }
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body

  try {
    const user = await UserRepository.login({ username, password })
    const token = jwt.sign(
      { id: user._id, username: user.username },
      JWT_SECRET_KEY,
      { expiresIn: '1h' }
    )

    res
      .cookie('access_token', token, {
        httpOnly: true, // solo desde el servidor
        sameSite: 'strict', // solo en el mismo dominio
        secure: isProduction() // solo con https
      })
      .status(200)
      .send({ user, token })
  } catch (error) {
    res.status(401).send(error.message)
  }
})

app.post('/logout', (req, res) => {
  res.clearCookie('access_token').json({ message: 'Logout successful' })
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
