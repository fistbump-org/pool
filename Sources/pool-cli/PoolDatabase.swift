#if canImport(SQLite3)
import SQLite3
#else
import CSQLite3
#endif
import Foundation
import Logging

/// SQLite-backed persistence for pool blocks, balances, and payouts.
public final class PoolDatabase: @unchecked Sendable {
    private var db: OpaquePointer?
    private let lock = NSLock()
    private let logger: Logger

    public init(path: String, logger: Logger) throws {
        self.logger = logger
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        let rc = sqlite3_open_v2(path, &db, flags, nil)
        guard rc == SQLITE_OK else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            throw PoolDatabaseError.openFailed(msg)
        }
        exec("PRAGMA journal_mode=WAL")
        exec("PRAGMA foreign_keys=ON")
        try createSchema()
        logger.info("Database opened: \(path)", source: "DB")
    }

    deinit {
        if let db { sqlite3_close(db) }
    }

    // MARK: - Schema

    private func createSchema() throws {
        let sql = """
        CREATE TABLE IF NOT EXISTS blocks (
            height        INTEGER PRIMARY KEY,
            hash          TEXT    NOT NULL UNIQUE,
            reward        INTEGER NOT NULL,
            found_at      INTEGER NOT NULL,
            confirmations INTEGER NOT NULL DEFAULT 0,
            status        TEXT    NOT NULL DEFAULT 'immature',
            credited      INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS block_shares (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            block_height  INTEGER NOT NULL REFERENCES blocks(height),
            address       TEXT    NOT NULL,
            difficulty    REAL    NOT NULL,
            fraction      REAL    NOT NULL,
            credit        INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_bs_height ON block_shares(block_height);

        CREATE TABLE IF NOT EXISTS balances (
            address       TEXT    PRIMARY KEY,
            balance       INTEGER NOT NULL DEFAULT 0,
            total_earned  INTEGER NOT NULL DEFAULT 0,
            total_paid    INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS payouts (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            txid          TEXT    NOT NULL,
            address       TEXT    NOT NULL,
            amount        INTEGER NOT NULL,
            status        TEXT    NOT NULL DEFAULT 'sent',
            created_at    INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_payouts_addr ON payouts(address);

        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO schema_version (rowid, version) VALUES (1, 1);
        """
        exec(sql)
    }

    // MARK: - Block Operations

    public func insertBlock(height: Int, hash: String, reward: Int64, foundAt: Date) {
        lock.lock(); defer { lock.unlock() }
        let ts = Int64(foundAt.timeIntervalSince1970)
        var stmt: OpaquePointer?
        let sql = "INSERT OR IGNORE INTO blocks (height, hash, reward, found_at) VALUES (?, ?, ?, ?)"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int64(stmt, 1, Int64(height))
        sqlite3_bind_text(stmt, 2, (hash as NSString).utf8String, -1, nil)
        sqlite3_bind_int64(stmt, 3, reward)
        sqlite3_bind_int64(stmt, 4, ts)
        if sqlite3_step(stmt) != SQLITE_DONE {
            logger.error("Failed to insert block \(height)", source: "DB")
        }
    }

    public func updateBlockConfirmations(height: Int, confirmations: Int) {
        lock.lock(); defer { lock.unlock() }
        exec("UPDATE blocks SET confirmations = \(confirmations) WHERE height = \(height)")
    }

    public func markBlockMature(height: Int) {
        lock.lock(); defer { lock.unlock() }
        exec("UPDATE blocks SET status = 'mature' WHERE height = \(height)")
    }

    public func markBlockOrphan(height: Int) {
        lock.lock(); defer { lock.unlock() }
        exec("UPDATE blocks SET status = 'orphan' WHERE height = \(height)")
    }

    public func markBlockCredited(height: Int) {
        lock.lock(); defer { lock.unlock() }
        exec("UPDATE blocks SET credited = 1 WHERE height = \(height)")
    }

    public func isBlockRecorded(height: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return queryInt("SELECT COUNT(*) FROM blocks WHERE height = \(height)") > 0
    }

    public struct BlockRecord: Sendable {
        public let height: Int
        public let hash: String
        public let reward: Int64
        public let foundAt: Date
        public let confirmations: Int
        public let status: String
        public let credited: Bool
    }

    public func getImmatureBlocks() -> [BlockRecord] {
        lock.lock(); defer { lock.unlock() }
        return queryBlocks("SELECT * FROM blocks WHERE status = 'immature' ORDER BY height")
    }

    public func getAllBlocks(limit: Int = 100) -> [BlockRecord] {
        lock.lock(); defer { lock.unlock() }
        return queryBlocks("SELECT * FROM blocks ORDER BY height DESC LIMIT \(limit)")
    }

    public func getBlockCount() -> Int {
        lock.lock(); defer { lock.unlock() }
        return queryInt("SELECT COUNT(*) FROM blocks WHERE status != 'orphan'")
    }

    // MARK: - Block Shares

    public struct ShareRecord: Sendable {
        public let address: String
        public let difficulty: Double
        public let fraction: Double
        public let credit: Int64
    }

    public func insertBlockShares(blockHeight: Int, shares: [(address: String, difficulty: Double, fraction: Double, credit: Int64)]) {
        lock.lock(); defer { lock.unlock() }
        exec("BEGIN")
        for s in shares {
            var stmt: OpaquePointer?
            let sql = "INSERT INTO block_shares (block_height, address, difficulty, fraction, credit) VALUES (?, ?, ?, ?, ?)"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { continue }
            sqlite3_bind_int64(stmt, 1, Int64(blockHeight))
            sqlite3_bind_text(stmt, 2, (s.address as NSString).utf8String, -1, nil)
            sqlite3_bind_double(stmt, 3, s.difficulty)
            sqlite3_bind_double(stmt, 4, s.fraction)
            sqlite3_bind_int64(stmt, 5, s.credit)
            sqlite3_step(stmt)
            sqlite3_finalize(stmt)
        }
        exec("COMMIT")
    }

    public func getBlockShares(blockHeight: Int) -> [ShareRecord] {
        lock.lock(); defer { lock.unlock() }
        var results: [ShareRecord] = []
        var stmt: OpaquePointer?
        let sql = "SELECT address, difficulty, fraction, credit FROM block_shares WHERE block_height = ?"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return results }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int64(stmt, 1, Int64(blockHeight))
        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append(ShareRecord(
                address: String(cString: sqlite3_column_text(stmt, 0)),
                difficulty: sqlite3_column_double(stmt, 1),
                fraction: sqlite3_column_double(stmt, 2),
                credit: sqlite3_column_int64(stmt, 3)
            ))
        }
        return results
    }

    // MARK: - Balance Operations

    public func creditBalance(address: String, amount: Int64) {
        lock.lock(); defer { lock.unlock() }
        var stmt: OpaquePointer?
        let sql = """
            INSERT INTO balances (address, balance, total_earned, total_paid)
            VALUES (?, ?, ?, 0)
            ON CONFLICT(address) DO UPDATE SET
                balance = balance + excluded.balance,
                total_earned = total_earned + excluded.total_earned
        """
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, (address as NSString).utf8String, -1, nil)
        sqlite3_bind_int64(stmt, 2, amount)
        sqlite3_bind_int64(stmt, 3, amount)
        sqlite3_step(stmt)
    }

    public func debitBalance(address: String, amount: Int64) {
        lock.lock(); defer { lock.unlock() }
        var stmt: OpaquePointer?
        let sql = "UPDATE balances SET balance = balance - ?, total_paid = total_paid + ? WHERE address = ?"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int64(stmt, 1, amount)
        sqlite3_bind_int64(stmt, 2, amount)
        sqlite3_bind_text(stmt, 3, (address as NSString).utf8String, -1, nil)
        sqlite3_step(stmt)
    }

    public func getAllBalances() -> [(address: String, balance: Int64, totalEarned: Int64, totalPaid: Int64)] {
        lock.lock(); defer { lock.unlock() }
        var results: [(String, Int64, Int64, Int64)] = []
        var stmt: OpaquePointer?
        let sql = "SELECT address, balance, total_earned, total_paid FROM balances WHERE balance > 0 OR total_earned > 0 ORDER BY balance DESC"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return results }
        defer { sqlite3_finalize(stmt) }
        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append((
                String(cString: sqlite3_column_text(stmt, 0)),
                sqlite3_column_int64(stmt, 1),
                sqlite3_column_int64(stmt, 2),
                sqlite3_column_int64(stmt, 3)
            ))
        }
        return results
    }

    public func getPendingPayouts(minBalance: Int64) -> [(address: String, amount: Int64)] {
        lock.lock(); defer { lock.unlock() }
        var results: [(String, Int64)] = []
        var stmt: OpaquePointer?
        let sql = "SELECT address, balance FROM balances WHERE balance >= ?"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return results }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int64(stmt, 1, minBalance)
        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append((
                String(cString: sqlite3_column_text(stmt, 0)),
                sqlite3_column_int64(stmt, 1)
            ))
        }
        return results
    }

    // MARK: - Payout Operations

    public struct PayoutRecord: Sendable {
        public let txid: String
        public let address: String
        public let amount: Int64
        public let status: String
        public let createdAt: Date
    }

    public func insertPayout(txid: String, address: String, amount: Int64) {
        lock.lock(); defer { lock.unlock() }
        let ts = Int64(Date().timeIntervalSince1970)
        var stmt: OpaquePointer?
        let sql = "INSERT INTO payouts (txid, address, amount, status, created_at) VALUES (?, ?, ?, 'sent', ?)"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, (txid as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 2, (address as NSString).utf8String, -1, nil)
        sqlite3_bind_int64(stmt, 3, amount)
        sqlite3_bind_int64(stmt, 4, ts)
        sqlite3_step(stmt)
    }

    public func getRecentPayouts(limit: Int = 100) -> [PayoutRecord] {
        lock.lock(); defer { lock.unlock() }
        var results: [PayoutRecord] = []
        var stmt: OpaquePointer?
        let sql = "SELECT txid, address, amount, status, created_at FROM payouts ORDER BY created_at DESC LIMIT ?"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return results }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, Int32(limit))
        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append(PayoutRecord(
                txid: String(cString: sqlite3_column_text(stmt, 0)),
                address: String(cString: sqlite3_column_text(stmt, 1)),
                amount: sqlite3_column_int64(stmt, 2),
                status: String(cString: sqlite3_column_text(stmt, 3)),
                createdAt: Date(timeIntervalSince1970: Double(sqlite3_column_int64(stmt, 4)))
            ))
        }
        return results
    }

    // MARK: - Migration from JSON

    public func importFromJSON(path: String) {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return
        }

        lock.lock(); defer { lock.unlock() }
        exec("BEGIN")

        if let bals = json["balances"] as? [String: Any] {
            for (addr, val) in bals {
                let amount = (val as? Int64) ?? Int64(val as? Double ?? 0)
                var stmt: OpaquePointer?
                let sql = "INSERT OR IGNORE INTO balances (address, balance, total_earned, total_paid) VALUES (?, ?, ?, 0)"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { continue }
                sqlite3_bind_text(stmt, 1, (addr as NSString).utf8String, -1, nil)
                sqlite3_bind_int64(stmt, 2, amount)
                sqlite3_bind_int64(stmt, 3, amount)
                sqlite3_step(stmt)
                sqlite3_finalize(stmt)
            }
        }

        if let paid = json["total_paid"] as? [String: Any] {
            for (addr, val) in paid {
                let amount = (val as? Int64) ?? Int64(val as? Double ?? 0)
                var stmt: OpaquePointer?
                let sql = "UPDATE balances SET total_paid = ?, total_earned = balance + ? WHERE address = ?"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { continue }
                sqlite3_bind_int64(stmt, 1, amount)
                sqlite3_bind_int64(stmt, 2, amount)
                sqlite3_bind_text(stmt, 3, (addr as NSString).utf8String, -1, nil)
                sqlite3_step(stmt)
                sqlite3_finalize(stmt)
            }
        }

        if let payouts = json["payouts"] as? [[String: Any]] {
            for p in payouts {
                guard let addr = p["address"] as? String,
                      let txid = p["txid"] as? String else { continue }
                let amount = (p["amount"] as? Int64) ?? Int64(p["amount"] as? Double ?? 0)
                let time = (p["time"] as? Int64) ?? Int64(p["time"] as? Double ?? 0)
                var stmt: OpaquePointer?
                let sql = "INSERT INTO payouts (txid, address, amount, status, created_at) VALUES (?, ?, ?, 'sent', ?)"
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { continue }
                sqlite3_bind_text(stmt, 1, (txid as NSString).utf8String, -1, nil)
                sqlite3_bind_text(stmt, 2, (addr as NSString).utf8String, -1, nil)
                sqlite3_bind_int64(stmt, 3, amount)
                sqlite3_bind_int64(stmt, 4, time)
                sqlite3_step(stmt)
                sqlite3_finalize(stmt)
            }
        }

        exec("COMMIT")
        logger.info("Imported state from \(path)", source: "DB")
    }

    public func isEmpty() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return queryInt("SELECT COUNT(*) FROM balances") == 0
            && queryInt("SELECT COUNT(*) FROM blocks") == 0
    }

    // MARK: - Helpers

    @discardableResult
    private func exec(_ sql: String) -> Bool {
        var err: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &err)
        if rc != SQLITE_OK {
            let msg = err.map { String(cString: $0) } ?? "unknown"
            sqlite3_free(err)
            logger.error("SQL error: \(msg)", source: "DB")
            return false
        }
        return true
    }

    private func queryInt(_ sql: String) -> Int {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return 0 }
        defer { sqlite3_finalize(stmt) }
        return sqlite3_step(stmt) == SQLITE_ROW ? Int(sqlite3_column_int64(stmt, 0)) : 0
    }

    private func queryBlocks(_ sql: String) -> [BlockRecord] {
        var results: [BlockRecord] = []
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return results }
        defer { sqlite3_finalize(stmt) }
        while sqlite3_step(stmt) == SQLITE_ROW {
            results.append(BlockRecord(
                height: Int(sqlite3_column_int64(stmt, 0)),
                hash: String(cString: sqlite3_column_text(stmt, 1)),
                reward: sqlite3_column_int64(stmt, 2),
                foundAt: Date(timeIntervalSince1970: Double(sqlite3_column_int64(stmt, 3))),
                confirmations: Int(sqlite3_column_int64(stmt, 4)),
                status: String(cString: sqlite3_column_text(stmt, 5)),
                credited: sqlite3_column_int64(stmt, 6) != 0
            ))
        }
        return results
    }
}

enum PoolDatabaseError: Error, CustomStringConvertible {
    case openFailed(String)

    var description: String {
        switch self {
        case .openFailed(let msg): return "Failed to open database: \(msg)"
        }
    }
}
