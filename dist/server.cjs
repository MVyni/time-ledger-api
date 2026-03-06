"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/app.ts
var import_express3 = __toESM(require("express"), 1);

// src/env/index.ts
var import_zod = require("zod");
var import_config = require("dotenv/config");
var envSchema = import_zod.z.object({
  NODE_ENV: import_zod.z.enum(["dev", "test", "production"]).default("dev"),
  PORT: import_zod.z.coerce.number().default(3333),
  DATABASE_URL: import_zod.z.string(),
  JWT_SECRET: import_zod.z.string()
});
var _env = envSchema.safeParse(process.env);
if (_env.success === false) {
  console.error("\u274C Invalid environment variables", import_zod.z.treeifyError(_env.error));
  throw new Error("Invalid environment variables!");
}
var env = _env.data;

// src/app.ts
var import_zod7 = require("zod");

// src/http/controllers/users/routes.ts
var import_express = require("express");

// src/lib/prisma.ts
var import_adapter_pg = require("@prisma/adapter-pg");

// src/generated/prisma/client.ts
var process2 = require("process");
var path = __toESM(require("path"), 1);
var import_node_url = require("url");
var runtime3 = require("@prisma/client/runtime/client");

// src/generated/prisma/internal/class.ts
var runtime = __toESM(require("@prisma/client/runtime/client"), 1);
var config = {
  "previewFeatures": [],
  "clientVersion": "7.2.0",
  "engineVersion": "0c8ef2ce45c83248ab3df073180d5eda9e8be7a3",
  "activeProvider": "postgresql",
  "inlineSchema": '// This is your Prisma schema file,\n// learn more about it in the docs: https://pris.ly/d/prisma-schema\n\n// Looking for ways to speed up your queries, or scale easily with your serverless or edge functions?\n// Try Prisma Accelerate: https://pris.ly/cli/accelerate-init\n\ngenerator client {\n  provider = "prisma-client"\n  output   = "../src/generated/prisma"\n}\n\ndatasource db {\n  provider = "postgresql"\n}\n\nmodel User {\n  id            String   @id @default(uuid())\n  name          String\n  email         String   @unique\n  password_hash String\n  created_at    DateTime @default(now())\n\n  entries WorkEntrie[]\n\n  @@map("users")\n}\n\nmodel WorkEntrie {\n  id                  String   @id @default(uuid())\n  date                DateTime\n  duration_minutes    Int\n  hourly_rate_at_time Decimal  @db.Decimal(10, 2)\n\n  user    User   @relation(fields: [user_id], references: [id])\n  user_id String\n\n  @@index([user_id, date])\n  @@map("work_entries")\n}\n',
  "runtimeDataModel": {
    "models": {},
    "enums": {},
    "types": {}
  }
};
config.runtimeDataModel = JSON.parse('{"models":{"User":{"fields":[{"name":"id","kind":"scalar","type":"String"},{"name":"name","kind":"scalar","type":"String"},{"name":"email","kind":"scalar","type":"String"},{"name":"password_hash","kind":"scalar","type":"String"},{"name":"created_at","kind":"scalar","type":"DateTime"},{"name":"entries","kind":"object","type":"WorkEntrie","relationName":"UserToWorkEntrie"}],"dbName":"users"},"WorkEntrie":{"fields":[{"name":"id","kind":"scalar","type":"String"},{"name":"date","kind":"scalar","type":"DateTime"},{"name":"duration_minutes","kind":"scalar","type":"Int"},{"name":"hourly_rate_at_time","kind":"scalar","type":"Decimal"},{"name":"user","kind":"object","type":"User","relationName":"UserToWorkEntrie"},{"name":"user_id","kind":"scalar","type":"String"}],"dbName":"work_entries"}},"enums":{},"types":{}}');
async function decodeBase64AsWasm(wasmBase64) {
  const { Buffer: Buffer2 } = await import("buffer");
  const wasmArray = Buffer2.from(wasmBase64, "base64");
  return new WebAssembly.Module(wasmArray);
}
config.compilerWasm = {
  getRuntime: async () => await import("@prisma/client/runtime/query_compiler_bg.postgresql.mjs"),
  getQueryCompilerWasmModule: async () => {
    const { wasm } = await import("@prisma/client/runtime/query_compiler_bg.postgresql.wasm-base64.mjs");
    return await decodeBase64AsWasm(wasm);
  }
};
function getPrismaClientClass() {
  return runtime.getPrismaClient(config);
}

// src/generated/prisma/internal/prismaNamespace.ts
var runtime2 = __toESM(require("@prisma/client/runtime/client"), 1);
var getExtensionContext = runtime2.Extensions.getExtensionContext;
var NullTypes2 = {
  DbNull: runtime2.NullTypes.DbNull,
  JsonNull: runtime2.NullTypes.JsonNull,
  AnyNull: runtime2.NullTypes.AnyNull
};
var TransactionIsolationLevel = runtime2.makeStrictEnum({
  ReadUncommitted: "ReadUncommitted",
  ReadCommitted: "ReadCommitted",
  RepeatableRead: "RepeatableRead",
  Serializable: "Serializable"
});
var defineExtension = runtime2.Extensions.defineExtension;

// src/generated/prisma/client.ts
var import_meta = {};
globalThis["__dirname"] = path.dirname((0, import_node_url.fileURLToPath)(import_meta.url));
var PrismaClient = getPrismaClientClass();

// src/lib/prisma.ts
var schema = new URL(env.DATABASE_URL).searchParams.get("schema") || "public";
var adapter = new import_adapter_pg.PrismaPg({ connectionString: env.DATABASE_URL }, { schema });
var prisma = new PrismaClient({
  adapter,
  log: env.NODE_ENV === "dev" ? ["query"] : []
});

// src/repositories/prisma/prisma-users-repository.ts
var PrismaUsersRepository = class {
  async create(data) {
    const user = await prisma.user.create({
      data
    });
    return user;
  }
  async findByEmail(email) {
    const user = await prisma.user.findUnique({
      where: {
        email
      }
    });
    return user;
  }
  async findById(id) {
    const user = await prisma.user.findUnique({
      where: {
        id
      }
    });
    return user;
  }
};

// src/services/errors/user-already-exists-error.ts
var UserAlreadyExistsError = class extends Error {
  constructor() {
    super("E-mail already exists.");
  }
};

// src/services/user/register.ts
var import_bcryptjs = require("bcryptjs");
var RegisterUserService = class {
  constructor(usersRepository) {
    this.usersRepository = usersRepository;
  }
  async execute({
    name,
    email,
    password
  }) {
    const password_hash = await (0, import_bcryptjs.hash)(password, 6);
    const userWithSameEmail = await this.usersRepository.findByEmail(email);
    if (userWithSameEmail) {
      throw new UserAlreadyExistsError();
    }
    const user = await this.usersRepository.create({
      name,
      email,
      password_hash
    });
    return { user };
  }
};

// src/services/factories/users/make-register-user-service.ts
function makeRegisterUserService() {
  const usersRepository = new PrismaUsersRepository();
  const useCase = new RegisterUserService(usersRepository);
  return useCase;
}

// src/http/controllers/users/register.ts
var import_zod2 = __toESM(require("zod"), 1);
async function registerUser(req, res) {
  const registerBodySchema = import_zod2.default.object({
    name: import_zod2.default.string(),
    email: import_zod2.default.email(),
    password: import_zod2.default.string().min(6)
  });
  const { name, email, password } = registerBodySchema.parse(req.body);
  const registerUserService = makeRegisterUserService();
  await registerUserService.execute({
    name,
    email,
    password
  });
  return res.status(201).send();
}

// src/services/errors/invalid-credentials-error.ts
var InvalidCredentialsError = class extends Error {
  constructor() {
    super("Invalid credentials.");
  }
};

// src/services/user/authenticate.ts
var import_bcryptjs2 = require("bcryptjs");

// src/utils/jwt-create.ts
var import_jsonwebtoken = __toESM(require("jsonwebtoken"), 1);
var TokenGenerate = class {
  constructor() {
  }
  execute({ user_id, email }) {
    const secret = env.JWT_SECRET;
    const token = import_jsonwebtoken.default.sign(
      {
        email
      },
      secret,
      {
        subject: user_id,
        expiresIn: "7d"
      }
    );
    return { token };
  }
};

// src/services/user/authenticate.ts
var AuthenticateService = class {
  constructor(usersRepository) {
    this.usersRepository = usersRepository;
  }
  async execute({
    email,
    password
  }) {
    const user = await this.usersRepository.findByEmail(email);
    if (!user) {
      throw new InvalidCredentialsError();
    }
    const doesPasswordMatch = await (0, import_bcryptjs2.compare)(password, user.password_hash);
    if (!doesPasswordMatch) {
      throw new InvalidCredentialsError();
    }
    return { user };
  }
};

// src/services/factories/users/make-auth-user-service.ts
function makeAuthenticateUserService() {
  const usersRepository = new PrismaUsersRepository();
  const useCase = new AuthenticateService(usersRepository);
  return useCase;
}

// src/http/controllers/users/authenticate.ts
var import_zod3 = require("zod");
async function authenticate(req, res) {
  const authBodySchema = import_zod3.z.object({
    email: import_zod3.z.email(),
    password: import_zod3.z.string().min(6)
  });
  const { email, password } = authBodySchema.parse(req.body);
  const authenticateUserService = makeAuthenticateUserService();
  const { user } = await authenticateUserService.execute({
    email,
    password
  });
  const tokenGenerate = new TokenGenerate();
  const { token } = tokenGenerate.execute({
    user_id: user.id,
    email: user.email
  });
  return res.status(200).send({ token });
}

// src/services/errors/resource-not-found-error.ts
var ResourceNotFoundError = class extends Error {
  constructor() {
    super("Resource not found.");
  }
};

// src/services/user/get-profile.ts
var GetUserProfileService = class {
  constructor(usersRepository) {
    this.usersRepository = usersRepository;
  }
  async execute({ userId }) {
    const user = await this.usersRepository.findById(userId);
    if (!user) {
      throw new ResourceNotFoundError();
    }
    return { user };
  }
};

// src/services/factories/users/make-get-user-profile-service.ts
function makeGetUserProfileService() {
  const usersRepository = new PrismaUsersRepository();
  const useCase = new GetUserProfileService(usersRepository);
  return useCase;
}

// src/http/controllers/users/me.ts
async function me(req, res) {
  const userId = req.user.user_id;
  const getUserProfileService = makeGetUserProfileService();
  const { user } = await getUserProfileService.execute({ userId });
  return res.status(200).send({
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      created_at: user.created_at
    }
  });
}

// src/http/middlewares/verify-jwt.ts
var import_jsonwebtoken2 = __toESM(require("jsonwebtoken"), 1);
function verifyJwt(req, res, next) {
  const authToken = req.headers.authorization;
  if (!authToken) {
    return res.status(401).send({ message: "Token is missing" });
  }
  const token = authToken.split(" ")[1];
  if (!token) {
    return res.status(401).send({ message: "Unauthorized" });
  }
  try {
    const { sub } = import_jsonwebtoken2.default.verify(token, env.JWT_SECRET);
    req.user = {
      user_id: sub
    };
  } catch (err) {
    return res.status(401).send({ message: "Unauthorized" });
  }
  next();
}

// src/http/controllers/users/routes.ts
var userRoutes = (0, import_express.Router)();
userRoutes.post("/register", registerUser);
userRoutes.post("/session", authenticate);
userRoutes.get("/me", verifyJwt, me);

// src/http/controllers/work-entries/routes.ts
var import_express2 = require("express");

// src/repositories/prisma/prisma-work-entries.repository.ts
var import_dayjs = __toESM(require("dayjs"), 1);
var PrismaWorkEntriesRepository = class {
  async create(data) {
    const workEntry = await prisma.workEntrie.create({
      data
    });
    return workEntry;
  }
  async update(id, data) {
    const workEntry = await prisma.workEntrie.update({
      where: {
        id
      },
      data
    });
    return workEntry;
  }
  async delete(id) {
    await prisma.workEntrie.delete({
      where: {
        id
      }
    });
  }
  async findByUserIdOnDate(userId, date) {
    const startOfTheDay = (0, import_dayjs.default)(date).startOf("date");
    const endOfTheDay = (0, import_dayjs.default)(date).endOf("date");
    const workEntrie = await prisma.workEntrie.findFirst({
      where: {
        user_id: userId,
        date: {
          gte: startOfTheDay.toDate(),
          lte: endOfTheDay.toDate()
        }
      }
    });
    return workEntrie;
  }
  async findById(id) {
    const workEntry = await prisma.workEntrie.findUnique({
      where: {
        id
      }
    });
    return workEntry;
  }
  async findMonthlyHistory(userId) {
    const entries = await prisma.workEntrie.findMany({
      where: {
        user_id: userId
      },
      orderBy: {
        date: "desc"
      }
    });
    const historyMap = entries.reduce(
      (acc, entry) => {
        const date = (0, import_dayjs.default)(entry.date);
        const key = date.format("YYYY-MM");
        if (!acc[key]) {
          acc[key] = {
            year: date.year(),
            month: date.month() + 1,
            totalMinutes: 0,
            totalEarnings: 0
          };
        }
        acc[key].totalMinutes += entry.duration_minutes;
        acc[key].totalEarnings += entry.duration_minutes / 60 * Number(entry.hourly_rate_at_time);
        return acc;
      },
      {}
    );
    return Object.values(historyMap).map((item) => ({
      ...item,
      totalEarnings: Number(item.totalEarnings.toFixed(2))
    })).sort((a, b) => b.year - a.year || b.month - a.month);
  }
  async findManyEntriesByUser(userId) {
    const workEntries = await prisma.workEntrie.findMany({
      where: {
        user_id: userId
      },
      orderBy: {
        date: "asc"
      }
    });
    return workEntries;
  }
};

// src/services/errors/max-daily-of-work-entrie-error.ts
var MaxDailyOfWorkEntriesError = class extends Error {
  constructor() {
    super("Max of daily work entrie.");
  }
};

// src/services/work-entries/create.ts
var CreateWorkEntriesService = class {
  constructor(workEntriesRepository) {
    this.workEntriesRepository = workEntriesRepository;
  }
  async execute({
    userId,
    date,
    durationMinutes,
    hourlyRateAtTime
  }) {
    const workEntrieOnSameDate = await this.workEntriesRepository.findByUserIdOnDate(userId, date);
    if (workEntrieOnSameDate) {
      throw new MaxDailyOfWorkEntriesError();
    }
    const workEntrie = await this.workEntriesRepository.create({
      user_id: userId,
      date,
      duration_minutes: durationMinutes,
      hourly_rate_at_time: hourlyRateAtTime
    });
    return { workEntrie };
  }
};

// src/services/factories/work-entries/make-create-work-entrie-service.ts
function makeCreateWorkEntrieService() {
  const workEntriesRepository = new PrismaWorkEntriesRepository();
  const service = new CreateWorkEntriesService(workEntriesRepository);
  return service;
}

// src/http/controllers/work-entries/create.ts
var import_zod4 = __toESM(require("zod"), 1);
async function createWorkEntries(req, res) {
  const createWorkEntrieBodySchema = import_zod4.default.object({
    date: import_zod4.default.coerce.date(),
    durationMinutes: import_zod4.default.number(),
    hourlyRateAtTime: import_zod4.default.number()
  });
  const { date, durationMinutes, hourlyRateAtTime } = createWorkEntrieBodySchema.parse(req.body);
  const createWorkEntrieService = makeCreateWorkEntrieService();
  await createWorkEntrieService.execute({
    userId: req.user.user_id,
    date,
    durationMinutes,
    hourlyRateAtTime
  });
  return res.status(201).send({ message: "Work entry created successfully" });
}

// src/services/work-entries/update.ts
var UpdateWorkEntriesService = class {
  constructor(workEntriesRepository) {
    this.workEntriesRepository = workEntriesRepository;
  }
  async execute({
    workEntryId,
    userId,
    date,
    durationMinutes,
    hourlyRateAtTime
  }) {
    const workEntryExist = await this.workEntriesRepository.findById(workEntryId);
    if (!workEntryExist) {
      throw new ResourceNotFoundError();
    }
    if (workEntryExist.user_id !== userId) {
      throw new ResourceNotFoundError();
    }
    const workEntrieOnSameDate = await this.workEntriesRepository.findByUserIdOnDate(userId, date);
    if (workEntrieOnSameDate && workEntrieOnSameDate.id !== workEntryId) {
      throw new MaxDailyOfWorkEntriesError();
    }
    const workEntrie = await this.workEntriesRepository.update(workEntryId, {
      date,
      duration_minutes: durationMinutes,
      hourly_rate_at_time: hourlyRateAtTime
    });
    return { workEntrie };
  }
};

// src/services/factories/work-entries/make-update-work-entries-service.ts
function makeUpdateWorkEntrieService() {
  const workEntriesRepository = new PrismaWorkEntriesRepository();
  const service = new UpdateWorkEntriesService(workEntriesRepository);
  return service;
}

// src/http/controllers/work-entries/update.ts
var import_zod5 = __toESM(require("zod"), 1);
async function updateWorkEntries(req, res) {
  const updateWorkEntryBodySchema = import_zod5.default.object({
    date: import_zod5.default.coerce.date(),
    durationMinutes: import_zod5.default.number(),
    hourlyRateAtTime: import_zod5.default.number()
  });
  const updateWorkEntryParamsSchema = import_zod5.default.object({ workEntryId: import_zod5.default.string() });
  const { date, durationMinutes, hourlyRateAtTime } = updateWorkEntryBodySchema.parse(req.body);
  const { workEntryId } = updateWorkEntryParamsSchema.parse(req.params);
  const updateWorkEntrieService = makeUpdateWorkEntrieService();
  const { workEntrie } = await updateWorkEntrieService.execute({
    workEntryId,
    userId: req.user.user_id,
    date,
    durationMinutes,
    hourlyRateAtTime
  });
  return res.status(200).send({ workEntrie });
}

// src/services/work-entries/delete.ts
var DeleteWorkEntriesService = class {
  constructor(workEntriesRepository) {
    this.workEntriesRepository = workEntriesRepository;
  }
  async execute({
    workEntryId,
    userId
  }) {
    const workEntryExist = await this.workEntriesRepository.findById(workEntryId);
    if (!workEntryExist) {
      throw new ResourceNotFoundError();
    }
    if (workEntryExist.user_id !== userId) {
      throw new ResourceNotFoundError();
    }
    await this.workEntriesRepository.delete(workEntryId);
  }
};

// src/services/factories/work-entries/make-delete-work-entries-service.ts
function makeDeleteWorkEntrieService() {
  const workEntriesRepository = new PrismaWorkEntriesRepository();
  const service = new DeleteWorkEntriesService(workEntriesRepository);
  return service;
}

// src/http/controllers/work-entries/delete.ts
var import_zod6 = __toESM(require("zod"), 1);
async function deleteWorkEntries(req, res) {
  const deleteWorkEntryParamsSchema = import_zod6.default.object({ workEntryId: import_zod6.default.string() });
  const { workEntryId } = deleteWorkEntryParamsSchema.parse(req.params);
  const deleteWorkEntrieService = makeDeleteWorkEntrieService();
  await deleteWorkEntrieService.execute({
    workEntryId,
    userId: req.user.user_id
  });
  return res.status(204).send();
}

// src/services/work-entries/fetch-history.ts
var FetchUserHistoryService = class {
  constructor(workEntriesRepository) {
    this.workEntriesRepository = workEntriesRepository;
  }
  async execute({ userId }) {
    const monthlyHistory = await this.workEntriesRepository.findMonthlyHistory(userId);
    return { monthlyHistory };
  }
};

// src/services/factories/work-entries/make-fetch-user-history-service.ts
function makeFetchUserHistoryService() {
  const workEntriesRepository = new PrismaWorkEntriesRepository();
  const service = new FetchUserHistoryService(workEntriesRepository);
  return service;
}

// src/http/controllers/work-entries/fetch-history.ts
async function history(req, res) {
  const fetchUserHistoryService = makeFetchUserHistoryService();
  const { monthlyHistory } = await fetchUserHistoryService.execute({
    userId: req.user.user_id
  });
  return res.status(200).send({ monthlyHistory });
}

// src/services/work-entries/fetch-entries.ts
var FetchUserEntriesService = class {
  constructor(workEntriesRepository) {
    this.workEntriesRepository = workEntriesRepository;
  }
  async execute({ userId }) {
    const entries = await this.workEntriesRepository.findManyEntriesByUser(userId);
    return { entries };
  }
};

// src/services/factories/work-entries/make-fetch-user-entries-service.ts
function makeFetchUserEntriesService() {
  const workEntriesRepository = new PrismaWorkEntriesRepository();
  const service = new FetchUserEntriesService(workEntriesRepository);
  return service;
}

// src/http/controllers/work-entries/fetch-entries.ts
async function list(req, res) {
  const fetchUserEntriesService = makeFetchUserEntriesService();
  const { entries } = await fetchUserEntriesService.execute({
    userId: req.user.user_id
  });
  return res.status(200).send({ entries });
}

// src/http/controllers/work-entries/routes.ts
var workEntrieRoutes = (0, import_express2.Router)();
workEntrieRoutes.post("/create", verifyJwt, createWorkEntries);
workEntrieRoutes.get("/history", verifyJwt, history);
workEntrieRoutes.get("/list", verifyJwt, list);
workEntrieRoutes.put("/update/:workEntryId", verifyJwt, updateWorkEntries);
workEntrieRoutes.delete("/delete/:workEntryId", verifyJwt, deleteWorkEntries);

// src/app.ts
var app = (0, import_express3.default)();
app.use(import_express3.default.json());
app.use("/user", userRoutes);
app.use("/workentrie", workEntrieRoutes);
app.use((err, _req, res, _next) => {
  if (err instanceof import_zod7.ZodError) {
    return res.status(400).send({
      message: "Validation error. ",
      issues: err.issues
    });
  }
  if (err instanceof InvalidCredentialsError) {
    return res.status(400).send({ message: err.message });
  }
  if (err instanceof MaxDailyOfWorkEntriesError) {
    return res.status(409).send({ message: err.message });
  }
  if (err instanceof ResourceNotFoundError) {
    return res.status(404).send({ message: err.message });
  }
  if (err instanceof UserAlreadyExistsError) {
    return res.status(409).send({ message: err.message });
  }
  if (env.NODE_ENV !== "production") {
    console.error(err);
  }
  return res.status(500).send({ message: "\u274C Internal server error" });
});

// src/server.ts
app.listen({
  hostname: "0.0.0.0",
  port: env.PORT
}, () => {
  console.log("\u{1F680} Server is running!");
});
//# sourceMappingURL=server.cjs.map