import { PrismaUsersRepository } from '@/repositories/prisma/prisma-users-repository.js'
import { GetUserProfileService } from '@/services/user/get-profile.js'

export function makeGetUserProfileService() {
  const usersRepository = new PrismaUsersRepository()
  const useCase = new GetUserProfileService(usersRepository)

  return useCase
}
