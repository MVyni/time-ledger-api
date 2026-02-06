import request from 'supertest'
import type { Express } from 'express'
import { beforeAll, describe, expect, it } from 'vitest'
import { createAndAuthUser } from '@/http/middlewares/test/create-and-auth-user.js'

describe('Update Work Entry (e2e)', () => {
  let app: Express

  beforeAll(async () => {
    app = (await import('@/app.js')).app
  })

  it('should be able to update a work entry', async () => {
    const { token } = await createAndAuthUser(app)

    await request(app)
      .post('/workentrie/create')
      .set('Authorization', `Bearer ${token}`)
      .send({
        date: new Date(),
        durationMinutes: 60,
        hourlyRateAtTime: 50,
      })

    const listResponse = await request(app)
      .get('/workentrie/list')
      .set('Authorization', `Bearer ${token}`)

    const workEntryId = listResponse.body.entries[0].id

    const response = await request(app)
      .put(`/workentrie/update/${workEntryId}`)
      .set('Authorization', `Bearer ${token}`)
      .send({
        date: new Date(),
        durationMinutes: 120,
        hourlyRateAtTime: 100,
      })

    expect(response.statusCode).toEqual(200)
    expect(response.body.workEntrie).toEqual(
      expect.objectContaining({
        duration_minutes: 120,
        hourly_rate_at_time: '100',
      })
    )
  })
})
