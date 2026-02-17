import type { Request, Response } from 'express'

import { makeGetUserProfileService } from '@/services/factories/users/make-get-user-profile-service.js'

export async function me(req: Request, res: Response) {
  const userId = req.user.user_id

  const getUserProfileService = makeGetUserProfileService()
  const { user } = await getUserProfileService.execute({ userId })

  return res.status(200).send({
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      created_at: user.created_at,
    },
  })
}
