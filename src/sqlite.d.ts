declare module "node:sqlite" {
  class DatabaseSync {
    constructor(location: string, options?: DatabaseSyncOptions);
    prepare(sql: string): StatementSync;
    close(): void;
  }

  interface DatabaseSyncOptions {
    open?: boolean;
    readOnly?: boolean;
  }

  class StatementSync {
    run(...params: unknown[]): DatabaseSyncRunResult;
    get(...params: unknown[]): unknown | undefined;
    all(...params: unknown[]): unknown[];
  }

  interface DatabaseSyncRunResult {
    changes: number;
    lastInsertRowid: number | bigint;
  }
}
