# Time Ledger App ⏳

API developed for time tracking and management. With this application, you can log your work entries, track duration, and calculate earnings based on hourly rates.

## Table of Contents 📌

- [About the Project](#about-the-project-)
- [How to Run the Project](#how-to-run-the-project-)
  - [Prerequisites](#prerequisites)
  - [Environment Variables](#environment-variables)
  - [Database (Docker)](#database-docker)
  - [Installation and Execution](#installation-and-execution)
  - [Running Tests](#running-tests)
- [API Routes](#api-routes)
- [Architecture](#architecture-)
- [Technologies](#technologies-)
- [License](#license-)

## About the Project 🔗

**Time Ledger App** is a RESTful application developed with **Node.js** and **Express**, designed to help users track their work hours and earnings. The application allows users to register work entries, recording the duration and the hourly rate applicable at that time.

### Key Features

#### User Management
- **User Registration**: Create new accounts with name, email, and password.
- **Authentication**: Authentication system using JWT (JSON Web Tokens) to protect API routes.

#### Work Entry Management
- **Entry Registration**: Log work entries with:
  - Date
  - Duration (in minutes)
  - Hourly rate at the time
- **Entry Association**: All entries are linked to a specific user.

#### Security and Access Control
- Authentication required for operations.
- Passwords encrypted with bcryptjs.
- JWT tokens to maintain user session.

## How to Run the Project 🔧

Follow the instructions below to build and run the project simply and easily.

### Prerequisites

Make sure you have installed:

- **Node.js** (version 18 or higher)
- **PostgreSQL** (or Docker, recommended)
- **npm**

### Environment Variables

Create a `.env` file based on `.env.example`.

These variables are required/used by the app (see `src/env/index.ts`):

```env
NODE_ENV=dev
PORT=3333

# Database
DATABASE_URL="postgresql://docker:docker@localhost:5432/timeledger?schema=public"

# Authentication
JWT_SECRET="your-secret-here"
```

> Notes:
> - `PORT` defaults to `3333` if not provided.
> - `NODE_ENV` defaults to `dev` if not provided.

### Database (Docker)

This repository includes a `docker-compose.yml` for PostgreSQL.

Start the database:

```bash
docker compose up -d
```

Optional environment variables supported by `docker-compose.yml`:

- `POSTGRES_USER` (default: `docker`)
- `POSTGRES_PASSWORD` (default: `docker`)
- `POSTGRES_DB` (default: `timeledger`)

### Installation and Execution

1. Clone the repository:

```bash
git clone https://github.com/MVyni/time-ledger-api.git
cd time-ledger-api
```

2. Install dependencies:

```bash
npm install
```

3. Run database migrations (development/local):

```bash
npx prisma migrate dev
```

4. Start the server:

- Development mode (watch):
```bash
npm run dev
```

- Start (runs `prisma migrate deploy` and then starts the server):
```bash
npm start
```

The server runs by default at:

- `http://localhost:3333`

### Running Tests

```bash
npm test
# or for e2e
npm run test:e2e
```

## API Routes

Base URL: `http://localhost:3333`

### User Routes (`/user`)

- `POST /user/register` — Create a new user
- `POST /user/session` — Authenticate and get a JWT
- `GET /user/me` — Get current authenticated user (**requires JWT**)

### Work Entries Routes (`/workentrie`) (**requires JWT**)

- `POST /workentrie/create` — Create a work entry
- `GET /workentrie/history` — Fetch work entries history
- `GET /workentrie/list` — List work entries
- `PUT /workentrie/update/:workEntryId` — Update a work entry
- `DELETE /workentrie/delete/:workEntryId` — Delete a work entry

## Architecture 🏗️

**Time Ledger App** was developed following the principles of a RESTful architecture.

### Key Characteristics

#### RESTful Base
- The API follows REST principles.

#### Core Technologies
- **Node.js**: Runtime environment.
- **Express**: Fast, unopinionated, minimalist web framework for Node.js.
- **TypeScript**: Static typing.

#### Database
- **Prisma ORM**: Next-generation Node.js and TypeScript ORM.
- **PostgreSQL**: Relational database.

#### Security and Authentication
- **JWT**: Token-based authentication.
- **Bcryptjs**: Password hashing.

#### Data Validation
- **Zod**: Schema validation.

#### Testing
- **Vitest**: Testing framework.
- **Supertest**: HTTP assertions.

## Technologies 💻

### Main Dependencies
- **express**
- **prisma**
- **@prisma/client**
- **jsonwebtoken**
- **bcryptjs**
- **zod**
- **dayjs**
- **pg**
- **dotenv**

### Development Dependencies
- **typescript**
- **tsx**
- **tsup**
- **vitest**
- **supertest**
- **prettier**

## License

ISC
