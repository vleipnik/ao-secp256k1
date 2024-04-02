import Database from 'better-sqlite3'

export const [PROCESSES_TABLE] = [
  'processes'
]

const createProcesses = async (db) => db.prepare(
  `CREATE TABLE IF NOT EXISTS ${PROCESSES_TABLE}(
    id TEXT PRIMARY KEY,
    signature TEXT,
    data TEXT,
    anchor TEXT,
    owner TEXT,
    tags JSONB,
    block JSONB
  ) WITHOUT ROWID;`
).run()

let internalSqliteDb
export async function createSqliteClient ({ url }) {
  if (internalSqliteDb) return internalSqliteDb

  const db = Database(url)

  /**
   * TODO:
   * - Create indexes
   */
  await Promise.resolve()
    .then(() => createProcesses(db))

  return {
    query: async ({ sql, parameters }) => db.prepare(sql).all(...parameters),
    run: async ({ sql, parameters }) => db.prepare(sql).run(...parameters),
    db
  }
}

/**
 * This technically isn't the smallest char, but it's small enough for our needs
 */
export const COLLATION_SEQUENCE_MIN_CHAR = '0'