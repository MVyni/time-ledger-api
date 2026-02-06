import request from 'supertest'
import type { Express } from 'express'
import { beforeAll, describe, expect, it } from 'vitest'
import { createAndAuthUser } from '@/http/middlewares/test/create-and-auth-user.js'

describe('Create Work Entry (e2e)', () => {
  let app: Express

  beforeAll(async () => {
    app = (await import('@/app.js')).app
  })

  it('should be able to create a work entry', async () => {
      const { token } = await createAndAuthUser(app)

    const response = await request(app)
      .post('/workentrie/create')
      .set('Authorization', `Bearer ${token}`)
      .send({
        date: new Date(),
        durationMinutes: 60,
        hourlyRateAtTime: 50,
      })

    expect(response.statusCode).toEqual(201)
  })
})
