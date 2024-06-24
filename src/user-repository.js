import crypto from 'node:crypto'

import bcrypt from 'bcrypt'
import DBLocal from 'db-local'

import { BCRYPT_SALT_OR_ROUNDS } from './config.js'
import { UserValidation } from './user-validation.js'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})

export class UserRepository {
  static async create ({ username, password }) {
    UserValidation.username(username)
    UserValidation.password(password)

    const user = User.findOne({ username })

    if (user) {
      throw new Error('username already exists')
    }

    const id = crypto.randomUUID()
    const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_OR_ROUNDS)

    User.create({
      _id: id,
      username,
      password: hashedPassword
    }).save()

    return id
  }

  static async login ({ username, password }) {
    UserValidation.username(username)
    UserValidation.password(password)

    const user = User.findOne({ username })

    if (!user) {
      throw new Error('username does not exist')
    }

    const isValid = await bcrypt.compare(password, user.password)

    if (!isValid) {
      throw new Error('password is invalid')
    }

    const { password: _, ...publicUser } = user
    return publicUser
  }
}
