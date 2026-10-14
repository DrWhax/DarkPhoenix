import Foundation

/// Binary oracle protocol, matching gpu/oracle.py.
/// The external process owns apply / applyFault / applyReverse.
final class ExternalOracle: AttackTarget {
    let nr: Int
    let isEncrypt: Bool
    let hasReverse: Bool
    let knownLastMC: Bool?
    let command: String
    private let process: Process
    private let stdin: FileHandle
    private let reader: PipeReader
    private let batchSize = 2048

    init(command: String) throws {
        self.command = command
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sh")
        proc.arguments = ["-c", command]
        let input = Pipe()
        let output = Pipe()
        proc.standardInput = input
        proc.standardOutput = output
        proc.standardError = FileHandle.standardError
        let stdin = input.fileHandleForWriting
        let reader = PipeReader(output.fileHandleForReading)
        do {
            try proc.run()
        } catch {
            throw AttackError.fail("failed to start oracle: \(error)")
        }
        reader.start()
        do {
            try stdin.write(contentsOf: Data([1]))
        } catch {
            throw AttackError.fail("oracle hello write failed: \(error)")
        }
        let status = try reader.read(1)
        if status[0] != 0 {
            let msg = try Self.readError(reader)
            throw AttackError.fail("oracle hello failed: \(msg)")
        }
        let hello = try reader.read(7)
        let rounds = Int(hello[0])
        guard [10, 12, 14].contains(rounds) else {
            throw AttackError.fail("oracle round count \(rounds) is not 10, 12, or 14")
        }
        self.nr = rounds
        self.isEncrypt = hello[1] != 0
        self.hasReverse = hello[2] != 0
        switch hello[3] {
        case 1: self.knownLastMC = false
        case 2: self.knownLastMC = true
        default: self.knownLastMC = nil
        }
        self.isAuto = hello[4] != 0
        self.isDynamic = hello[5] != 0
        self.hasRandomInput = hello[6] != 0
        self.process = proc
        self.stdin = stdin
        self.reader = reader
    }

    let isAuto: Bool
    let isDynamic: Bool
    let hasRandomInput: Bool
    private var autoState = AutoFaultState()
    private var callbackOutputF: [Encoding16] = []
    private var callbackReverseMC = false

    func close() {
        if process.isRunning {
            try? stdin.write(contentsOf: Data([2]))
            process.waitUntilExit()
        }
    }

    func newThread() throws {
        try write(Data([8]))
        _ = try readStatus()
    }

    func getRandomInput(_ n: Int) throws -> [UInt8] {
        var req = Data([7])
        var count = UInt32(n).littleEndian
        withUnsafeBytes(of: &count) { req.append(contentsOf: $0) }
        try write(req)
        let status = try reader.read(1)
        if status[0] != 0 { throw AttackError.fail("oracle: \(try Self.readError(reader))") }
        return [UInt8](try reader.read(16))
    }

    func changeFaultPosition(_ fround: Int, _ fbytes: Int) throws {
        try write(Data([5, UInt8(fround), UInt8(fbytes)]))
        _ = try readStatus()
    }

    func removeFaultPosition(_ fround: Int, _ fbytes: Int) throws {
        try write(Data([6, UInt8(fround), UInt8(fbytes)]))
        _ = try readStatus()
    }

    func clearFaultPositions(fround: Int?, fbytes: Int?) throws {
        try autoState.clear(wb: self, fround: fround, fbytes: fbytes)
    }

    func prepareFaultRound(fround: Int, outputF: [Encoding16], reverseMC: Bool) throws {
        autoState.lastRound = fround
        if isDynamic {
            callbackOutputF = outputF
            callbackReverseMC = reverseMC
            let has2: UInt8 = hasSecondView(outputF: outputF, reverseMC: reverseMC) ? 1 : 0
            try write(Data([9, UInt8(fround), has2]))
            try servicePrepareCallbacks()
        }
        if isAuto {
            try autoState.select(wb: self, fround: fround, outputF: outputF, reverseMC: reverseMC)
        }
    }

    private func servicePrepareCallbacks() throws {
        while true {
            let tag = try reader.read(1)
            if tag[0] == 0 { return }
            if tag[0] == 1 { throw AttackError.fail("oracle: \(try Self.readError(reader))") }
            if tag[0] == 2 || tag[0] == 3 {
                let raw = [UInt8](try reader.read(16))
                let out = view(raw, encrypt: isEncrypt, outputF: callbackOutputF, reverseMC: callbackReverseMC, second: tag[0] == 3)
                try write(Data(out))
                continue
            }
            throw AttackError.fail("oracle prepare protocol tag \(tag[0])")
        }
    }

    private func readStatus() throws {
        let status = try reader.read(1)
        if status[0] != 0 { throw AttackError.fail("oracle: \(try Self.readError(reader))") }
    }

    func applyRaw(_ block: [UInt8]) throws -> [UInt8] {
        let raw = try evalJobs([Job.pack(block, faultRound: nil, byte: 0, xor: 0)])
        return Array(raw)
    }

    func applyFaultRaw(_ block: [UInt8], round: Int, byte: Int, xor: UInt8) throws -> [UInt8] {
        let raw = try evalJobs([Job.pack(block, faultRound: round, byte: UInt8(byte), xor: xor)])
        return Array(raw)
    }

    func applyReverseRaw(_ block: [UInt8]) throws -> [UInt8] {
        guard hasReverse else { throw AttackError.fail("oracle has no applyReverse") }
        var req = Data([4])
        var n = UInt32(1).littleEndian
        req.append(Data(bytes: &n, count: 4))
        req.append(contentsOf: block)
        try write(req)
        return try readBlocks(1)
    }

    func evalJobs(_ jobs: [Job]) throws -> [UInt8] {
        if jobs.isEmpty { return [] }
        var out = [UInt8]()
        out.reserveCapacity(jobs.count * 16)
        var done = 0
        var offset = 0
        while offset < jobs.count {
            let n = min(batchSize, jobs.count - offset)
            var req = Data([3])
            var count = UInt32(n).littleEndian
            req.append(Data(bytes: &count, count: 4))
            req.reserveCapacity(5 + n * 20)
            for j in jobs[offset..<offset + n] {
                let words = [j.w0, j.w1, j.w2, j.w3]
                words.withUnsafeBytes { req.append(contentsOf: $0) }
                var meta = j.meta.littleEndian
                withUnsafeBytes(of: &meta) { req.append(contentsOf: $0) }
            }
            try write(req)
            let blocks = try readBlocks(n)
            out.append(contentsOf: blocks)
            offset += n
            done += n
            if jobs.count >= 100_000 && (done % (batchSize * 32) == 0 || done == jobs.count) {
                print("  oracle \(done)/\(jobs.count)")
            }
        }
        return out
    }

    func step2(_ plains: [UInt8], faultRound: Int, faultBytes: [UInt8]) throws -> [UInt8] {
        var jobs = [Job]()
        jobs.reserveCapacity(16 * 256 * 256)
        for b in 0..<16 {
            for xi in 0..<256 {
                let src = (b * 256 + xi) * 16
                let pt = Array(plains[src..<src + 16])
                for fval in 0..<256 {
                    if fval == 0 {
                        jobs.append(Job.pack(pt, faultRound: nil, byte: 0, xor: 0))
                    } else {
                        jobs.append(Job.pack(pt, faultRound: faultRound, byte: faultBytes[b], xor: UInt8(fval)))
                    }
                }
            }
        }
        let raw = try evalJobs(jobs)
        var viewed = [UInt8](repeating: 0, count: raw.count)
        let n = raw.count / 16
        for i in 0..<n {
            let view = postShift(Array(raw[i * 16..<(i + 1) * 16]), encryptWB: isEncrypt)
            for j in 0..<16 { viewed[i * 16 + j] = view[j] }
        }
        return viewed
    }

    func searchStep1(mref: [UInt8], valueRef: [UInt8], doubleRS: Bool, maxTrials: Int) throws -> (flags: [UInt32], inputs: [UInt8]) {
        let slots = Step1Layout.slotCount
        var flags = [UInt32](repeating: 0, count: slots)
        var inputs = [UInt8](repeating: 0, count: slots * 16)
        for c in 0..<4 {
            for rs in 0..<3 {
                for row in 0..<4 {
                    let b = c * 4 + row
                    let sl = Step1Layout.slot(byte: b, rs: rs, value: Int(valueRef[b]))
                    flags[sl] = 1
                    for i in 0..<16 { inputs[sl * 16 + i] = mref[i] }
                }
            }
        }
        let batch = 4096
        var base: UInt64 = 0
        var trials = 0
        let t0 = mono()
        while !step1Done(flags) {
            if trials >= maxTrials {
                throw AttackError.fail("step1: gave up after \(trials) oracle trials")
            }
            let n = min(batch, maxTrials - trials)
            var jobs = [Job]()
            jobs.reserveCapacity(n)
            var plains = [[UInt8]]()
            plains.reserveCapacity(n)
            for i in 0..<n {
                let block = counterBlock(base + UInt64(i))
                plains.append(block)
                jobs.append(Job.pack(block, faultRound: nil, byte: 0, xor: 0))
            }
            let raw = try evalJobs(jobs)
            for i in 0..<n {
                var view = postShift(Array(raw[i * 16..<(i + 1) * 16]), encryptWB: isEncrypt)
                considerStep1(&view, input: plains[i], valueRef: valueRef, doubleRS: doubleRS, flags: &flags, inputs: &inputs)
            }
            base += UInt64(n)
            trials += n
            if trials == n || step1Done(flags) || trials % (batch * 8) == 0 {
                print(String(format: "  step1  %d trials  %d/4096 slots  %.0f ms", trials, step1Present(flags), elapsedMS(t0, mono())))
            }
        }
        return (flags, inputs)
    }

    private func readBlocks(_ n: Int) throws -> [UInt8] {
        let status = try reader.read(1)
        if status[0] != 0 {
            throw AttackError.fail("oracle: \(try Self.readError(reader))")
        }
        let data = try reader.read(n * 16)
        return [UInt8](data)
    }

    private static func readError(_ reader: PipeReader) throws -> String {
        let lenData = try reader.read(4)
        let len = Int(lenData.withUnsafeBytes { $0.load(as: UInt32.self) }.littleEndian)
        let msg = try reader.read(len)
        return String(decoding: msg, as: UTF8.self)
    }

    private func write(_ data: Data) throws {
        do {
            try stdin.write(contentsOf: data)
        } catch {
            throw AttackError.fail("oracle write failed (process exited?): \(error)")
        }
    }
}

func counterBlock(_ v: UInt64) -> [UInt8] {
    var block = [UInt8](repeating: 0, count: 16)
    var x = v
    for k in 0..<8 {
        block[15 - k] = UInt8(truncatingIfNeeded: x)
        x >>= 8
    }
    return block
}

final class PipeReader {
    private let handle: FileHandle
    private let cond = NSCondition()
    private var buf = Data()
    private var eof = false

    init(_ handle: FileHandle) {
        self.handle = handle
    }

    func start() {
        handle.readabilityHandler = { [weak self] h in
            guard let self else { return }
            let data = h.availableData
            self.cond.lock()
            if data.isEmpty {
                self.eof = true
            } else {
                self.buf.append(data)
            }
            self.cond.signal()
            self.cond.unlock()
        }
    }

    func read(_ n: Int) throws -> Data {
        cond.lock()
        defer { cond.unlock() }
        while buf.count < n && !eof {
            cond.wait()
        }
        if buf.count < n {
            throw AttackError.fail("oracle closed the pipe early")
        }
        let out = buf.prefix(n)
        buf.removeFirst(n)
        return Data(out)
    }
}
