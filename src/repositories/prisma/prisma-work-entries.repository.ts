import type { Prisma, WorkEntrie } from '@/generated/prisma/client.js'
import type { WorkEntriesRepository } from '../work-entries-repository.js'
import { prisma } from '@/lib/prisma.js'

import dayjs from 'dayjs'
import type { MonthlyHistory } from '../work-entries-repository.js'

export class PrismaWorkEntriesRepository implements WorkEntriesRepository {
  async create(data: Prisma.WorkEntrieUncheckedCreateInput) {
    const workEntry = await prisma.workEntrie.create({
      data,
    })

    return workEntry
  }

  async update(id: string, data: Prisma.WorkEntrieUncheckedUpdateInput) {
    const workEntry = await prisma.workEntrie.update({
      where: {
        id,
      },

      data,
    })

    return workEntry
  }

  async delete(id: string) {
    await prisma.workEntrie.delete({
      where: {
        id,
      },
    })
  }

  async findByUserIdOnDate(userId: string, date: Date) {
    const startOfTheDay = dayjs(date).startOf('date')
    const endOfTheDay = dayjs(date).endOf('date')

    const workEntrie = await prisma.workEntrie.findFirst({
      where: {
        user_id: userId,
        date: {
          gte: startOfTheDay.toDate(),
          lte: endOfTheDay.toDate(),
        },
      },
    })

    return workEntrie
  }

  async findById(id: string) {
    const workEntry = await prisma.workEntrie.findUnique({
      where: {
        id,
      },
    })

    return workEntry
  }

  async findMonthlyHistory(userId: string): Promise<MonthlyHistory[]> {
    const result = await prisma.$queryRaw<
      {
        year: number
        month: number
        totalMinutes: number
        totalEarnings: number
      }[]
    >`
      SELECT
        CAST(EXTRACT(YEAR FROM date) AS INTEGER) as "year",
        CAST(EXTRACT(MONTH FROM date) AS INTEGER) as "month",
        CAST(SUM(duration_minutes) AS INTEGER) as "totalMinutes",
        CAST(SUM( (duration_minutes::NUMERIC / 60.0) * hourly_rate_at_time) AS FLOAT) as "totalEarnings"
      FROM
        work_entries
      WHERE
        user_id = ${userId}
      GROUP BY 
        EXTRACT(YEAR FROM date),
        EXTRACT(MONTH FROM date)
      ORDER BY
        "year" DESC, "month" DESC
    `

    return result.map((row) => ({
      year: row.year,
      month: row.month,
      totalMinutes: row.totalMinutes,
      totalEarnings: row.totalEarnings,
    }))
  }
    
  async findManyEntriesByUser(userId: string) {
    const workEntries = await prisma.workEntrie.findMany({
      where: {
        user_id: userId,
      },
      orderBy: {
        date: 'asc',
      },
    })

    return workEntries
  }
}
