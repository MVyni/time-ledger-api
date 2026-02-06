import type { WorkEntrie } from '@/generated/prisma/client.js'
import type {  WorkEntriesRepository } from '@/repositories/work-entries-repository.js'

interface FetchUserEntriesServiceRequest {
    userId: string
}

interface FetchUserEntriesServiceResponse {
  entries: WorkEntrie[]
}

export class FetchUserEntriesService {
    constructor(private workEntriesRepository: WorkEntriesRepository) { }

    async execute({ userId }: FetchUserEntriesServiceRequest): Promise<FetchUserEntriesServiceResponse> {

        const entries = await this.workEntriesRepository.findManyEntriesByUser(userId)
        
        return { entries }
    }
}