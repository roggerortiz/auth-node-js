import { NODE_ENV_ENUM } from './enum.js'

export const isProduction = () => {
  return process.env.NODE_ENV?.toLowerCase()?.trim() === NODE_ENV_ENUM.PRODUCTION
}

export const getEnvFilePath = () => {
  return isProduction() ? '.env.production' : undefined
}
