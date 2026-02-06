import { prisma } from '@/lib/prisma.js'
import { hash } from 'bcryptjs'
import type { Express } from 'express'
import request from 'supertest'

export async function createAndAuthUser(app: Express) {
  await prisma.user.create({
    data: {
      name: 'John Doe',
      email: 'johndoe@example.com',
      password_hash: await hash('123456', 6),
    },
  })

  const authResponse = await request(app).post('/user/session').send({
    email: 'johndoe@example.com',
    password: '123456',
  })

    const { token } = authResponse.body

    return { token }
}
