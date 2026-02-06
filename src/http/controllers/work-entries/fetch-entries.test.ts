import request from 'supertest'
import type { Express } from 'express'
import { beforeAll, describe, expect, it } from 'vitest'
import { createAndAuthUser } from '@/http/middlewares/test/create-and-auth-user.js'

describe('Fetch Work Entries (e2e)', () => {
  let app: Express

  beforeAll(async () => {
    app = (await import('@/app.js')).app
  })

  it('should be able to list work entries', async () => {
    const { token } = await createAndAuthUser(app)

    await request(app)
      .post('/workentrie/create')
      .set('Authorization', `Bearer ${token}`)
      .send({
        date: new Date('2026-01-01'),
        durationMinutes: 60,
        hourlyRateAtTime: 50,
      })

    await request(app)
      .post('/workentrie/create')
      .set('Authorization', `Bearer ${token}`)
      .send({
        date: new Date('2026-01-02'),
        durationMinutes: 120,
        hourlyRateAtTime: 60,
      })

    const response = await request(app)
      .get('/workentrie/list')
      .set('Authorization', `Bearer ${token}`)
      .send()

    expect(response.statusCode).toEqual(200)
    expect(response.body.entries).toHaveLength(2)
    expect(response.body.entries).toEqual([
      expect.objectContaining({
        duration_minutes: 60,
        hourly_rate_at_time: '50',
      }),
      expect.objectContaining({
        duration_minutes: 120,
        hourly_rate_at_time: '60',
      }),
    ])
  })
})
