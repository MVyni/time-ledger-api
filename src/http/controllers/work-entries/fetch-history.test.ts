import request from 'supertest'
import type { Express } from 'express'
import { beforeAll, describe, expect, it } from 'vitest'
import { createAndAuthUser } from '@/http/middlewares/test/create-and-auth-user.js'

describe('Fetch Work Entries History (e2e)', () => {
  let app: Express

  beforeAll(async () => {
    app = (await import('@/app.js')).app
  })

  it('should be able to fetch work entries history', async () => {
    const { token } = await createAndAuthUser(app)

    await request(app)
      .post('/workentrie/create')
      .set('Authorization', `Bearer ${token}`)
      .send({
        date: new Date('2026-01-03'),
        durationMinutes: 60,
        hourlyRateAtTime: 50,
      })

    await request(app)
      .post('/workentrie/create')
      .set('Authorization', `Bearer ${token}`)
      .send({
        date: new Date('2026-01-04'),
        durationMinutes: 60,
        hourlyRateAtTime: 50,
      })

    const response = await request(app)
      .get('/workentrie/history')
      .set('Authorization', `Bearer ${token}`)
      .send()

    expect(response.statusCode).toEqual(200)
    expect(response.body.monthlyHistory).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          totalEarnings: 100,
        }),
      ])
    )
  })
})
