import Foundation

/// Variable difficulty algorithm.
///
/// Adjusts per-worker share difficulty so each worker submits shares at
/// approximately the target rate. This prevents slow miners from never
/// submitting shares and fast miners from overwhelming the server.
public struct VarDiff: Sendable {
    public let targetTime: Double
    public let minDiff: Double
    public let maxDiff: Double
    public let retargetInterval: Double
    public let variance: Double

    public init(config: PoolConfig) {
        self.targetTime = config.vardiffTargetTime
        self.minDiff = config.vardiffMinDiff
        self.maxDiff = config.vardiffMaxDiff
        self.retargetInterval = config.vardiffRetargetTime
        self.variance = config.vardiffVariance
    }

    /// Check if a worker needs a difficulty adjustment and return the new difficulty, or nil.
    public func retarget(worker: PoolWorker) -> Double? {
        let now = Date()
        let elapsed = now.timeIntervalSince(worker.lastRetargetTime)
        guard elapsed >= retargetInterval else { return nil }

        guard let avgTime = worker.averageShareTime else {
            // Not enough data yet — if they've been connected a while with no shares,
            // lower the difficulty.
            if elapsed > retargetInterval * 2 && worker.difficulty > minDiff {
                return max(worker.difficulty / 2, minDiff)
            }
            return nil
        }

        let ratio = avgTime / targetTime

        // Within tolerance band — no adjustment needed
        if ratio >= (1.0 - variance) && ratio <= (1.0 + variance) {
            return nil
        }

        // Adjust: if shares are too slow, decrease difficulty; if too fast, increase.
        // Clamp the adjustment factor to avoid wild swings.
        let factor = min(max(ratio, 0.25), 4.0)
        var newDiff = worker.difficulty * factor

        // Clamp to bounds
        newDiff = max(newDiff, minDiff)
        newDiff = min(newDiff, maxDiff)

        // Round to a clean value (power-of-2 friendly)
        newDiff = roundDifficulty(newDiff)

        // Don't bother if the change is tiny
        if abs(newDiff - worker.difficulty) / worker.difficulty < 0.05 {
            return nil
        }

        return newDiff
    }

    /// Round difficulty to a "nice" value.
    private func roundDifficulty(_ d: Double) -> Double {
        if d < 1 { return max(d, minDiff) }
        // Round to 3 significant figures
        let magnitude = pow(10, floor(log10(d)))
        return (d / magnitude).rounded() * magnitude
    }
}
