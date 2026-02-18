import { Router } from 'express'

import { registerUser } from './register.js'
import { authenticate } from './authenticate.js'
import { me } from './me.js'
import { verifyJwt } from '@/http/middlewares/verify-jwt.js'

export const userRoutes = Router()

userRoutes.post('/register', registerUser)
userRoutes.post('/session', authenticate)
userRoutes.get('/me', verifyJwt, me)
