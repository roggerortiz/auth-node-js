import { getEnvFilePath } from './utils.js'

// 20.14.0 => run script 'node --env-file=.env src/index.js'

// >= 21.7.0
// si no se envia parametro (path = undefined), usa '.env' por defecto
process.loadEnvFile(getEnvFilePath())

export const {
  PORT = 3000,
  BCRYPT_SALT_OR_ROUNDS = 10, // Produccion = 10, Development = 4,
  JWT_SECRET_KEY
} = process.env
