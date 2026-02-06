import type { Prisma, WorkEntrie } from '@/generated/prisma/client.js'
import type { WorkEntriesRepository } from '../work-entries-repository.js'
import { prisma } from '@/lib/prisma.js'

import dayjs from 'dayjs'

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

  async findMonthlyHistory(userId: string) {
    const entries = await prisma.workEntrie.findMany({
      where: {
        user_id: userId,
      },
      orderBy: {
        date: 'desc',
      },
    })

    const historyMap = entries.reduce(
      (acc, entry) => {
        const date = dayjs(entry.date)
        const key = date.format('YYYY-MM')

        if (!acc[key]) {
          acc[key] = {
            year: date.year(),
            month: date.month() + 1,
            totalMinutes: 0,
            totalEarnings: 0,
          }
        }

        acc[key].totalMinutes += entry.duration_minutes
        acc[key].totalEarnings +=
          (entry.duration_minutes / 60) * Number(entry.hourly_rate_at_time)

        return acc
      },
      {} as Record<
        string,
        {
          year: number
          month: number
          totalMinutes: number
          totalEarnings: number
        }
      >
    )

    return Object.values(historyMap)
      .map((item) => ({
        ...item,
        totalEarnings: Number(item.totalEarnings.toFixed(2)),
      }))
      .sort((a, b) => b.year - a.year || b.month - a.month)
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
