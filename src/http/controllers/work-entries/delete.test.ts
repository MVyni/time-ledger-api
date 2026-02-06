import request from 'supertest'
import type { Express } from 'express'
import { beforeAll, describe, expect, it } from 'vitest'
import { createAndAuthUser } from '@/http/middlewares/test/create-and-auth-user.js'

describe('Delete Work Entry (e2e)', () => {
  let app: Express

  beforeAll(async () => {
    app = (await import('@/app.js')).app
  })

  it('should be able to delete a work entry', async () => {
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
      .delete(`/workentrie/delete/${workEntryId}`)
      .set('Authorization', `Bearer ${token}`)

    expect(response.statusCode).toEqual(204)
  })
})
