import Foundation

protocol AttackTarget {
    var nr: Int { get }
    var isEncrypt: Bool { get }
    var knownLastMC: Bool? { get }
    func applyRaw(_ block: [UInt8]) throws -> [UInt8]
    func applyFaultRaw(_ block: [UInt8], round: Int, byte: Int, xor: UInt8) throws -> [UInt8]
    func applyReverseRaw(_ block: [UInt8]) throws -> [UInt8]
    func evalJobs(_ jobs: [Job]) throws -> [UInt8]
    func step2(_ plains: [UInt8], faultRound: Int, faultBytes: [UInt8]) throws -> [UInt8]
    func searchStep1(mref: [UInt8], valueRef: [UInt8], doubleRS: Bool, maxTrials: Int) throws -> (flags: [UInt32], inputs: [UInt8])
    var isAuto: Bool { get }
    var isDynamic: Bool { get }
    var hasRandomInput: Bool { get }
    func getRandomInput(_ n: Int) throws -> [UInt8]
    func prepareFaultRound(fround: Int, outputF: [Encoding16], reverseMC: Bool) throws
    func changeFaultPosition(_ fround: Int, _ fbytes: Int) throws
    func removeFaultPosition(_ fround: Int, _ fbytes: Int) throws
    func clearFaultPositions(fround: Int?, fbytes: Int?) throws
    func newThread() throws
}

extension AttackTarget {
    var knownLastMC: Bool? { nil }
    var isAuto: Bool { false }
    var isDynamic: Bool { false }
    var hasRandomInput: Bool { false }
    func getRandomInput(_ n: Int) throws -> [UInt8] {
        throw AttackError.fail("white-box does not implement getRandomInput")
    }
    func prepareFaultRound(fround: Int, outputF: [Encoding16], reverseMC: Bool) throws {}
    func changeFaultPosition(_ fround: Int, _ fbytes: Int) throws {}
    func removeFaultPosition(_ fround: Int, _ fbytes: Int) throws {}
    func clearFaultPositions(fround: Int?, fbytes: Int?) throws {}
    func newThread() throws {}
}

extension Whitebox: AttackTarget {}

struct Recovery {
    var key: [UInt8]
    var roundKeys: [[UInt8]]
    var inputEncoding: Encoding16?
    var outputEncoding: Encoding16?
    var milliseconds: Double
}

struct AttackConfig {
    var useReverse = true
    var doubleRS = false
    var wantEncodings = false
    var allRound = true
    var forceOffset: Int? = nil
    var backup: String? = nil
    var auto = false
    var retry = -1
}

func recover(wb: AttackTarget, mref: [UInt8], useReverse: Bool, doubleRS: Bool, wantEncodings: Bool, rng: inout SplitMix64) throws -> Recovery {
    try recover(wb: wb, mref: mref, config: AttackConfig(useReverse: useReverse, doubleRS: doubleRS, wantEncodings: wantEncodings), rng: &rng)
}

func recover(wb: AttackTarget, mref initialMref: [UInt8]?, config: AttackConfig, rng: inout SplitMix64) throws -> Recovery {
    if config.auto {
        var attempt = 0
        while true {
            do {
                return try recoverOnce(wb: wb, mref: initialMref, config: config, rng: &rng)
            } catch {
                if config.retry >= 0 && attempt >= config.retry { throw error }
                attempt += 1
                Log.progress("\(error): retry \(attempt)")
                if let fp = error as? FaultPositionError {
                    if let bytes = fp.bytes {
                        for b in bytes { try wb.clearFaultPositions(fround: fp.roundNumber, fbytes: b) }
                    } else {
                        try wb.clearFaultPositions(fround: fp.roundNumber, fbytes: nil)
                    }
                } else {
                    try wb.clearFaultPositions(fround: nil, fbytes: nil)
                }
            }
        }
    }
    return try recoverOnce(wb: wb, mref: initialMref, config: config, rng: &rng)
}

func recoverOnce(wb: AttackTarget, mref initialMref: [UInt8]?, config: AttackConfig, rng: inout SplitMix64) throws -> Recovery {
    let t0 = mono()
    try wb.newThread()
    var cp = Checkpoint()
    if let path = config.backup, FileManager.default.fileExists(atPath: path) {
        cp = try Checkpoint.load(path)
        Log.progress("restored state \(cp.state) from \(path)")
    }
    if !cp.haveMref {
        if let initialMref {
            cp.mref = initialMref
        } else if wb.hasRandomInput {
            cp.mref = try wb.getRandomInput(0)
        } else {
            cp.mref = rng.bytes(16)
        }
        cp.haveMref = true
    }
    let mref = cp.mref
    let lastMC = try wb.knownLastMC ?? detectLastMC(wb)
    Log.v("lastRoundHasMC=\(lastMC)")

    if cp.state < 1 {
        let step1: ([[UInt8]], [[Int]])
        if config.useReverse {
            let t = mono()
            step1 = try step1Reverse(wb, mref)
            Log.progress(String(format: "  step1 reverse   %6.1f ms", elapsedMS(t, mono())))
        } else {
            let raw = try wb.applyRaw(mref)
            let valueRef = postShift(raw, encryptWB: wb.isEncrypt)
            let maxTrials = config.doubleRS ? (256 << 20) : (8 << 20)
            let found = try wb.searchStep1(mref: mref, valueRef: valueRef, doubleRS: config.doubleRS, maxTrials: maxTrials)
            step1 = try selectStep1(flags: found.flags, inputs: found.inputs, doubleRS: config.doubleRS)
        }
        try verifyStep1(wb, mref, step1.0, step1.1)
        cp.M = step1.0
        cp.rs = step1.1
        cp.state = 1
        try cp.save(config.backup)
    }
    let (M, rs) = (cp.M, cp.rs)

    if cp.state < 2 {
        let t2 = mono()
        cp.gtilde = try step2(wb, M, rs, lastMC)
        Log.progress(String(format: "  step2           %6.1f ms", elapsedMS(t2, mono())))
        cp.state = 2
        try cp.save(config.backup)
    }
    let gtilde = cp.gtilde

    if cp.state < 3 {
        let t3 = mono()
        let solved = try step3(wb, gtilde, mref, lastMC)
        cp.gbarInv = solved.gbarInv
        cp.C = solved.C
        cp.roundShift = solved.roundShift
        Log.progress(String(format: "  step3           %6.1f ms  (linear convention %d)", elapsedMS(t3, mono()), solved.direction))
        cp.state = 3
        try cp.save(config.backup)
    }

    if cp.state < 4 {
        let t4 = mono()
        let pair = try step4(wb, gtilde, cp.gbarInv, cp.C, mref, lastMC, &rng)
        cp.lambda = pair.0
        cp.beta = pair.1
        Log.progress(String(format: "  step4           %6.1f ms", elapsedMS(t4, mono())))
        cp.state = 4
        try cp.save(config.backup)
    }

    if cp.state < 5 {
        let t5 = mono()
        cp.keyPart = try step5(wb, gtilde, cp.gbarInv, cp.C, cp.lambda, cp.beta, mref, lastMC, allRound: config.allRound, &rng)
        Log.progress(String(format: "  step5           %6.1f ms", elapsedMS(t5, mono())))
        cp.state = 5
        try cp.save(config.backup)
    }
    let roundKeys = cp.keyPart

    let key = try assembleKey(wb, roundKeys, forceOffset: config.forceOffset)
    printRoundKeys(roundKeys, nr: wb.nr, encrypt: wb.isEncrypt)
    var inputE: Encoding16?
    var outputE: Encoding16?
    if config.wantEncodings {
        let enc = try externalEncodings(wb, gtilde, cp.gbarInv, cp.C, cp.lambda, cp.beta, key)
        try verifyEncodings(wb, enc.input, enc.output, key)
        inputE = enc.input
        outputE = enc.output
    }
    return Recovery(key: key, roundKeys: roundKeys, inputEncoding: inputE, outputEncoding: outputE, milliseconds: elapsedMS(t0, mono()))
}

func detectLastMC(_ wb: AttackTarget) throws -> Bool {
    let z = [UInt8](repeating: 0, count: 16)
    let u = postShift(try wb.applyRaw(z), encryptWB: wb.isEncrypt)
    try wb.prepareFaultRound(fround: wb.nr - 1, outputF: [], reverseMC: false)
    let f = postShift(try wb.applyFaultRaw(z, round: wb.nr - 1, byte: 15, xor: 1), encryptWB: wb.isEncrypt)
    let n = zip(u, f).filter { $0 != $1 }.count
    if n == 1 { return false }
    if n == 4 { return true }
    throw AttackError.fail("cannot detect last-round MixColumns (differs in \(n) bytes)")
}

func step1Reverse(_ wb: AttackTarget, _ mref: [UInt8]) throws -> ([[UInt8]], [[Int]]) {
    let valueRef = postShift(try wb.applyRaw(mref), encryptWB: wb.isEncrypt)
    var M = [[UInt8]](repeating: [UInt8](repeating: 0, count: 256 * 16), count: 16)
    for b in 0..<16 {
        let off = Int(valueRef[b]) * 16
        for i in 0..<16 { M[b][off + i] = mref[i] }
    }
    for i in 1..<256 {
        var p1 = [UInt8](repeating: 0, count: 16)
        var p2 = [UInt8](repeating: 0, count: 16)
        let ib = UInt8(i)
        for c in 0..<4 {
            p1[c * 4] = ib
            p1[c * 4 + 1] = ib
            p2[c * 4 + 2] = ib
            p2[c * 4 + 3] = ib
        }
        let d1 = try wb.applyReverseRaw(preReverse(xorBytes(valueRef, p1), encryptWB: wb.isEncrypt))
        let d2 = try wb.applyReverseRaw(preReverse(xorBytes(valueRef, p2), encryptWB: wb.isEncrypt))
        for b in 0..<16 {
            let src = b % 4 < 2 ? d1 : d2
            let off = Int(valueRef[b] ^ ib) * 16
            for k in 0..<16 { M[b][off + k] = src[k] }
        }
    }
    let rs: [[Int]] = [
        [2, 3], [2, 3], [0, 1], [0, 1],
        [6, 7], [6, 7], [4, 5], [4, 5],
        [10, 11], [10, 11], [8, 9], [8, 9],
        [14, 15], [14, 15], [12, 13], [12, 13],
    ]
    return (M, rs)
}

func preReverse(_ data: [UInt8], encryptWB: Bool) -> [UInt8] {
    encryptWB ? shiftRow(data) : invShiftRow(data)
}

func verifyStep1(_ wb: AttackTarget, _ mref: [UInt8], _ M: [[UInt8]], _ rs: [[Int]]) throws {
    let valueRef = postShift(try wb.applyRaw(mref), encryptWB: wb.isEncrypt)
    var jobs: [Job] = []
    jobs.reserveCapacity(16 * 256)
    for b in 0..<16 {
        for xi in 0..<256 {
            jobs.append(Job.pack(Array(M[b][xi * 16..<(xi + 1) * 16]), faultRound: nil, byte: 0, xor: 0))
        }
    }
    let raw = try wb.evalJobs(jobs)
    for b in 0..<16 {
        for xi in 0..<256 {
            let off = (b * 256 + xi) * 16
            let view = postShift(Array(raw[off..<off + 16]), encryptWB: wb.isEncrypt)
            if view[b] != UInt8(xi) { throw AttackError.fail("step1 verify: byte \(b) value \(xi)") }
            for r in rs[b] where view[r] != valueRef[r] {
                throw AttackError.fail("step1 verify: companion \(r) for byte \(b)")
            }
        }
    }
}

func faultByteStep2(b: Int, pos: Int, nr: Int, encrypt: Bool, lastMC: Bool) -> (Int, Int) {
    let fpos = (b - (b % 4) + pos) % 16
    if lastMC { return (nr - 1, fpos) }
    if encrypt { return (nr - 2, Int(AESConst.shift[fpos])) }
    return (nr - 2, Int(AESConst.invShift[fpos]))
}

func step2(_ wb: AttackTarget, _ M: [[UInt8]], _ rs: [[Int]], _ lastMC: Bool) throws -> Encoding16 {
    let (prepRound, _) = faultByteStep2(b: 0, pos: 0, nr: wb.nr, encrypt: wb.isEncrypt, lastMC: lastMC)
    try wb.prepareFaultRound(fround: prepRound, outputF: [], reverseMC: false)
    var jobs: [Job] = []
    jobs.reserveCapacity(16 * 16 * 256)
    for b in 0..<16 {
        let pt = Array(M[b][0..<16])
        for pos in 0..<16 {
            let (fr, fb) = faultByteStep2(b: b, pos: pos, nr: wb.nr, encrypt: wb.isEncrypt, lastMC: lastMC)
            for fval in 0..<256 {
                if fval == 0 {
                    jobs.append(Job.pack(pt, faultRound: nil, byte: 0, xor: 0))
                } else {
                    jobs.append(Job.pack(pt, faultRound: fr, byte: UInt8(fb), xor: UInt8(fval)))
                }
            }
        }
    }
    let probe = try wb.evalJobs(jobs)
    var positions = [Int](repeating: -1, count: 16)
    var faultRound = 0
    for b in 0..<16 {
        let r = rs[b][0]
        let s = rs[b].count == 2 ? rs[b][1] : nil
        for pos in 0..<16 {
            var seen = [Bool](repeating: false, count: 256)
            var good = true
            for fval in 0..<256 {
                let idx = ((b * 16 + pos) * 256 + fval) * 16
                let view = postShift(Array(probe[idx..<idx + 16]), encryptWB: wb.isEncrypt)
                if fval == 0 && view[b] != 0 { good = false; break }
                let rv = Int(view[r])
                if seen[rv] { good = false; break }
                seen[rv] = true
                _ = s
            }
            if good && seen.allSatisfy({ $0 }) {
                positions[b] = pos
                let (fr, _) = faultByteStep2(b: b, pos: pos, nr: wb.nr, encrypt: wb.isEncrypt, lastMC: lastMC)
                faultRound = fr
                break
            }
        }
        if positions[b] < 0 { throw AttackError.fail("step2: no fault position for byte \(b) (round \(wb.nr - 2))") }
    }
    Log.v("step2 positions \(positions)")

    var faultBytes = [UInt8](repeating: 0, count: 16)
    var plains = [UInt8](repeating: 0, count: 16 * 256 * 16)
    for b in 0..<16 {
        let (_, fb) = faultByteStep2(b: b, pos: positions[b], nr: wb.nr, encrypt: wb.isEncrypt, lastMC: lastMC)
        faultBytes[b] = UInt8(fb)
        for xi in 0..<256 {
            let dst = (b * 256 + xi) * 16
            for i in 0..<16 { plains[dst + i] = M[b][xi * 16 + i] }
        }
    }
    let outs = try wb.step2(plains, faultRound: faultRound, faultBytes: faultBytes)
    var tables = [[UInt8]]()
    tables.reserveCapacity(16)
    try outs.withUnsafeBufferPointer { p in
        for b in 0..<16 {
            let r = rs[b][0]
            let sOpt = rs[b].count == 2 ? rs[b][1] : nil
            var R = [UInt8?](repeating: nil, count: 256)
            var rows = [[UInt8]](repeating: [UInt8](repeating: 0, count: 256), count: 256)
            for xi in 0..<256 {
                var seen = [Bool](repeating: false, count: 256)
                for fval in 0..<256 {
                    let base = ((b * 256 + xi) * 256 + fval) * 16
                    let ob = p[base + b]
                    let orv = p[base + r]
                    if fval == 0 && ob != UInt8(xi) {
                        throw AttackError.fail("step2: unfaulted byte \(b) xi \(xi) got \(ob)")
                    }
                    if seen[Int(orv)] { throw AttackError.fail("step2: duplicate companion on byte \(b)") }
                    seen[Int(orv)] = true
                    rows[Int(orv)][xi] = ob
                    if let s = sOpt {
                        let osv = p[base + s]
                        if xi == 0 {
                            if R[Int(orv)] != nil { throw AttackError.fail("step2: double-value collision") }
                            R[Int(orv)] = osv
                        } else if R[Int(orv)] != osv {
                            throw AttackError.fail("step2: double-value mismatch")
                        }
                    }
                }
            }
            tables.append(try tolhuizen(rows))
        }
    }
    return Encoding16(enc: tables)
}

func tolhuizen(_ rows: [[UInt8]]) throws -> [UInt8] {
    var S: [[UInt8]?] = Array(repeating: nil, count: 256)
    for s in rows {
        let k = Int(s[0])
        if S[k] != nil { throw AttackError.fail("Tolhuizen: duplicate pivot") }
        S[k] = s
    }
    var perm = [Int?](repeating: nil, count: 256)
    perm[0] = 0
    var i = 1
    for j in 0..<8 {
        while i < 256 && perm[i] != nil { i += 1 }
        if i >= 256 { throw AttackError.fail("Tolhuizen: ran out of pivots") }
        perm[i] = 1 << j
        guard let row = S[i] else { throw AttackError.fail("Tolhuizen: missing row \(i)") }
        let pi = perm[i]!
        for k in 1..<256 {
            if let pk = perm[k] {
                let m = Int(row[k])
                let expect = pk ^ pi
                if perm[m] == nil { perm[m] = expect }
                else if perm[m] != expect { throw AttackError.fail("Tolhuizen: inconsistent at \(m)") }
            }
        }
    }
    return try perm.map { v in
        guard let v else { throw AttackError.fail("Tolhuizen: incomplete permutation") }
        return UInt8(truncatingIfNeeded: v)
    }
}

struct ColFaults {
    var fpos: [Int] = []
    var words: [[[UInt8]]] = [] // [slot][fval][4]
}

func step3(_ wb: AttackTarget, _ gtilde: Encoding16, _ mref: [UInt8], _ lastMC: Bool) throws -> (gbarInv: Encoding16, C: [UInt8], direction: Int, roundShift: [Int]) {
    let fround = wb.nr - (lastMC ? 1 : 2)
    try wb.prepareFaultRound(fround: fround, outputF: [gtilde], reverseMC: false)
    let vref = attackView(try wb.applyRaw(mref), encryptWB: wb.isEncrypt, outputF: [gtilde], reverseMC: false)
    var jobs: [Job] = []
    jobs.reserveCapacity(16 * 255)
    for fpos in 0..<16 {
        for fval in 1...255 {
            jobs.append(Job.pack(mref, faultRound: fround, byte: UInt8(fpos), xor: UInt8(fval)))
        }
    }
    let raw = try wb.evalJobs(jobs)
    var W = [ColFaults(), ColFaults(), ColFaults(), ColFaults()]
    for fpos in 0..<16 {
        var column = -1
        var words = [[UInt8]](repeating: [], count: 256)
        words[0] = [] // filled once column known
        for fval in 1...255 {
            let idx = (fpos * 255 + (fval - 1)) * 16
            let view = attackView(Array(raw[idx..<idx + 16]), encryptWB: wb.isEncrypt, outputF: [gtilde], reverseMC: false)
            let diff = (0..<16).filter { view[$0] != vref[$0] }
            if diff.count != 4 { throw AttackError.fail("step3: fault \(fpos)/\(fval) touches \(diff.count) bytes") }
            let col = diff[0] / 4
            if diff != [col * 4, col * 4 + 1, col * 4 + 2, col * 4 + 3] {
                throw AttackError.fail("step3: fault \(fpos) is not a single column")
            }
            if fval == 1 {
                column = col
                words[0] = Array(vref[col * 4..<col * 4 + 4])
            } else if col != column {
                throw AttackError.fail("step3: fault \(fpos) changed column")
            }
            words[fval] = Array(view[col * 4..<col * 4 + 4])
        }
        guard column >= 0, W[column].fpos.count < 4 else {
            throw AttackError.fail("step3: column \(column) has too many fault positions")
        }
        W[column].fpos.append(fpos)
        W[column].words.append(words)
    }
    for c in 0..<4 where W[c].fpos.count != 4 {
        throw AttackError.fail("step3: column \(c) has \(W[c].fpos.count) faults, expected 4")
    }
    return try solveGbar(wb, W)
}

func solveGbar(_ wb: AttackTarget, _ W: [ColFaults]) throws -> (gbarInv: Encoding16, C: [UInt8], direction: Int, roundShift: [Int]) {
    let cands = candidateMatrices(encrypt: wb.isEncrypt)
    var maps = [[UInt8]]()
    var poss: [(Int, Int)] = []
    maps.reserveCapacity(16)
    let fposPair = [(0, 1), (2, 3), (1, 3), (2, 0)]
    for b in 0..<16 {
        let col = b / 4
        let p0 = b % 4
        let p1 = 2 * (p0 / 2) + ((p0 + 1) % 2)
        poss.append((p0, p1))
        let pair = fposPair[p0]
        let f0 = W[col].words[pair.0]
        let f1 = W[col].words[pair.1]
        if f0[0] != f1[0] { throw AttackError.fail("step3: fault bases differ on byte \(b)") }
        let base = f0[0]
        var w01 = [UInt8?](repeating: nil, count: 256)
        var w10 = [UInt8?](repeating: nil, count: 256)
        for p in 0..<256 {
            let i01 = Int(base[p0] ^ f0[p][p0])
            let i10 = Int(base[p1] ^ f1[p][p1])
            if w01[i01] != nil || w10[i10] != nil { throw AttackError.fail("step3: nonlinear differential on byte \(b)") }
            w01[i01] = base[p1] ^ f0[p][p1]
            w10[i10] = base[p0] ^ f1[p][p0]
        }
        var table = [UInt8](repeating: 0, count: 256)
        for x in 0..<256 {
            guard let a = w01[x], let y = w10[Int(a)] else { throw AttackError.fail("step3: incomplete map on byte \(b)") }
            table[x] = y
        }
        maps.append(table)
    }

    var viable: [(Int, [String])] = []
    for dir in 0..<8 {
        var names: [String] = []
        var ok = true
        for b in 0..<16 {
            let L = matFromMap(maps[b])
            var hits: [String] = []
            for cand in cands {
                let basis = intertwinerBasis(L: L, M: cand.1, direction: dir)
                if !invertibleFromBasis(basis, limit: 1).isEmpty { hits.append(cand.0) }
            }
            if hits.count != 1 { ok = false; break }
            names.append(hits[0])
        }
        if ok { viable.append((dir, names)) }
    }
    if viable.isEmpty {
        throw AttackError.fail("step3: no MixColumns matrix matched the fault differentials (Sage replacement found no similarity)")
    }

    for (dir, names) in viable {
        var associate = [[Int?]](repeating: [Int?](repeating: nil, count: 4), count: 4)
        var consistent = true
        for b in 0..<16 {
            let col = b / 4
            let (p0, p1) = poss[b]
            let pair = fposPair[p0]
            guard let rows = associateFault(name: names[b], p0: p0, p1: p1) else { consistent = false; break }
            for (slot, row) in [(pair.0, rows.0), (pair.1, rows.1)] {
                if let prev = associate[col][slot] {
                    if prev != row { consistent = false }
                } else if associate[col].contains(where: { $0 == row }) {
                    consistent = false
                } else {
                    associate[col][slot] = row
                }
            }
            if !consistent { break }
        }
        if !consistent || associate.contains(where: { $0.contains(where: { $0 == nil }) }) { continue }
        let assoc = associate.map { $0.map { $0! } }
        if let built = try? buildGbar(wb, W, maps, names, dir, cands, assoc, fposPair) {
            var roundShift = [Int](repeating: -1, count: 16)
            for ncol in 0..<4 {
                for (p, x) in zip(W[ncol].fpos, assoc[ncol]) {
                    roundShift[4 * ncol + x] = p
                }
            }
            return (built.inv, built.C, dir, roundShift)
        }
    }
    throw AttackError.fail("step3: differentials matched a matrix but the byte encoding was not consistent")
}

func buildGbar(_ wb: AttackTarget, _ W: [ColFaults], _ maps: [[UInt8]], _ names: [String], _ dir: Int, _ cands: [(String, Mat8)], _ assoc: [[Int]], _ fposPair: [(Int, Int)]) throws -> (inv: Encoding16, C: [UInt8]) {
    var encTables = [[UInt8]](repeating: [], count: 16)
    var invTables = [[UInt8]](repeating: [], count: 16)
    let byName = Dictionary(uniqueKeysWithValues: cands.map { ($0.0, $0.1) })
    for b in 0..<16 {
        let L = matFromMap(maps[b])
        guard let M = byName[names[b]] else { throw AttackError.fail("missing matrix \(names[b])") }
        let basis = intertwinerBasis(L: L, M: M, direction: dir)
        let gs = invertibleFromBasis(basis, limit: 48)
        if gs.isEmpty { throw AttackError.fail("no invertible encoding for byte \(b)") }
        let col = b / 4
        let row = b % 4
        var chosen: Mat8?
        if row == 0 {
            chosen = gs[0]
        } else {
            guard let slot0 = assoc[col].firstIndex(of: 0) else { throw AttackError.fail("no row-0 fault") }
            let wi0 = W[col].words[slot0]
            let g0inv = invTables[col * 4]
            let coef = cCoef(encrypt: wb.isEncrypt, row: row)
            for g in gs {
                let t = tableFromMat(g)
                if cValue(g0: g0inv, gb: inverseTable(t), wi0: wi0, row: row, coef: coef) != nil {
                    chosen = g
                    break
                }
            }
        }
        guard let g = chosen else { throw AttackError.fail("encoding gauge failed for byte \(b)") }
        let table = tableFromMat(g)
        encTables[b] = table
        invTables[b] = inverseTable(table)
    }
    var C = [UInt8](repeating: 1, count: 16)
    for b in 0..<16 where b % 4 != 0 {
        let col = b / 4
        let row = b % 4
        guard let slot0 = assoc[col].firstIndex(of: 0) else { throw AttackError.fail("no row-0 fault") }
        let coef = cCoef(encrypt: wb.isEncrypt, row: row)
        guard let ci = cValue(g0: invTables[col * 4], gb: invTables[b], wi0: W[col].words[slot0], row: row, coef: coef) else {
            throw AttackError.fail("C inconsistent for byte \(b)")
        }
        C[b] = ci
    }
    return (Encoding16(enc: invTables), C)
}

func inverseTable(_ enc: [UInt8]) -> [UInt8] {
    var d = [UInt8](repeating: 0, count: 256)
    for i in 0..<256 { d[Int(enc[i])] = UInt8(i) }
    return d
}

func cCoef(encrypt: Bool, row: Int) -> UInt8 {
    if encrypt { return row == 3 ? gmul(3, gfInv(2)) : gfInv(2) }
    if row == 1 { return gmul(9, gfInv(14)) }
    if row == 2 { return gmul(13, gfInv(14)) }
    return gmul(11, gfInv(14))
}

func cValue(g0: [UInt8], gb: [UInt8], wi0: [[UInt8]], row: Int, coef: UInt8) -> UInt8? {
    var ci: UInt8?
    for p in 0..<wi0.count {
        let ti = gb[Int(wi0[0][row] ^ wi0[p][row])]
        let t0 = g0[Int(wi0[0][0] ^ wi0[p][0])]
        if ti == 0 { continue }
        let v = gmul(gfInv(ti), gmul(t0, coef))
        if let c = ci {
            if c != v { return nil }
        } else {
            ci = v
        }
    }
    return ci
}

struct MeetCoef {
    static let enc: [[UInt8]] = [
        [0, 2, 2, gmul(2, gfInv(3))],
        [0, gmul(3, gfInv(2)), 3, 3],
        [0, gfInv(3), gfInv(2), 1],
        [0, 1, gfInv(3), gfInv(2)],
    ]
    static let dec: [[UInt8]] = [
        [0, gmul(14, gfInv(9)), gmul(14, gfInv(13)), gmul(14, gfInv(11))],
        [0, gmul(11, gfInv(14)), gmul(11, gfInv(9)), gmul(11, gfInv(13))],
        [0, gmul(13, gfInv(11)), gmul(13, gfInv(14)), gmul(13, gfInv(9))],
        [0, gmul(9, gfInv(13)), gmul(9, gfInv(11)), gmul(9, gfInv(14))],
    ]
}

func meet(col: Int, fault: [[UInt8]], midalpha: Int, encrypt: Bool, limited: [UInt8]?) -> (Bool, [UInt8], [UInt8]) {
    for fpos in 0..<4 {
        let res = meetAt(col: col, fault: fault, midalpha: midalpha, encrypt: encrypt, fpos: fpos, limited: limited)
        if res.0 { return res }
    }
    return (false, [], [])
}

func meetAt(col: Int, fault: [[UInt8]], midalpha: Int, encrypt: Bool, fpos: Int, limited: [UInt8]?) -> (Bool, [UInt8], [UInt8]) {
    let sb = encrypt ? AESConst.invSbox : AESConst.sbox
    let coefs = encrypt ? MeetCoef.enc[fpos] : MeetCoef.dec[fpos]
    let all = (1...255).map { UInt8($0) }
    let lim: [[UInt8]]
    if let limited {
        if encrypt {
            lim = [
                [limited[(4 - col) % 4]],
                [limited[(4 + 1 - col) % 4]],
                [limited[(4 + 2 - col) % 4]],
                [limited[(4 + 3 - col) % 4]],
            ]
        } else {
            lim = [
                [limited[col % 4]],
                [limited[(col + 1) % 4]],
                [limited[(col + 2) % 4]],
                [limited[(col + 3) % 4]],
            ]
        }
    } else {
        lim = [all, all, all, all]
    }
    let fault0 = Array(fault.prefix(midalpha + 1))
    let fault1 = [fault[0]] + Array(fault.suffix(from: midalpha + 1))
    var table: [UInt32: [(UInt8, UInt8)]] = [:]
    table.reserveCapacity(lim[0].count * 256)
    for lam in lim[0] {
        for beta in 0..<256 {
            let b = UInt8(beta)
            let v0 = sb[Int(gmul(lam, fault0[0][0]) ^ b)]
            var hash: UInt32 = 0
            for (i, x) in fault0.dropFirst().enumerated() {
                let d = v0 ^ sb[Int(gmul(lam, x[0]) ^ b)]
                hash |= UInt32(d) << (8 * i)
            }
            table[hash, default: []].append((lam, b))
        }
    }
    func solveRow(_ row: Int) -> [(UInt8, UInt8, UInt8, UInt8)] {
        var sols: [(UInt8, UInt8, UInt8, UInt8)] = []
        let coef = coefs[row]
        for lam in lim[row] {
            for beta in 0..<256 {
                let b = UInt8(beta)
                let v0 = sb[Int(gmul(lam, fault0[0][row]) ^ b)]
                var hash: UInt32 = 0
                for (i, x) in fault0.dropFirst().enumerated() {
                    let d = v0 ^ sb[Int(gmul(lam, x[row]) ^ b)]
                    hash |= UInt32(gmul(coef, d)) << (8 * i)
                }
                guard let hits = table[hash] else { continue }
                var second = [UInt8]()
                second.reserveCapacity(fault1.count - 1)
                for x in fault1.dropFirst() {
                    let d = v0 ^ sb[Int(gmul(lam, x[row]) ^ b)]
                    second.append(gmul(coef, d))
                }
                for (rl, rb) in hits {
                    let vR = sb[Int(gmul(rl, fault1[0][0]) ^ rb)]
                    var same = true
                    for (i, x) in fault1.dropFirst().enumerated() {
                        let d = vR ^ sb[Int(gmul(rl, x[0]) ^ rb)]
                        if d != second[i] { same = false; break }
                    }
                    if same { sols.append((rl, rb, lam, b)) }
                }
            }
        }
        return sols
    }
    let s1 = solveRow(1)
    if s1.count != 1 { return (false, [], []) }
    let s2 = solveRow(2)
    if s2.count != 1 { return (false, [], []) }
    let s3 = solveRow(3)
    if s3.count != 1 { return (false, [], []) }
    if s1[0].0 != s2[0].0 || s1[0].0 != s3[0].0 || s1[0].1 != s2[0].1 || s1[0].1 != s3[0].1 {
        return (false, [], [])
    }
    return (true, [s1[0].0, s1[0].2, s2[0].2, s3[0].2], [s1[0].1, s1[0].3, s2[0].3, s3[0].3])
}

func faultAt4(col: Int, pos: Int, nr: Int, encrypt: Bool, lastMC: Bool) -> (Int, Int) {
    let fpos = (col * 4 + pos) % 16
    let round = nr - (lastMC ? 2 : 3)
    let byte = encrypt ? Int(AESConst.shift[fpos]) : Int(AESConst.invShift[fpos])
    return (round, byte)
}

func faultAt5(col: Int, pos: Int, roundN: Int, nr: Int, encrypt: Bool, lastMC: Bool) -> (Int, Int) {
    let fpos = (col * 4 + pos) % 16
    let round = nr - (lastMC ? 3 : 4) - roundN
    let byte = encrypt ? Int(AESConst.shift[fpos]) : Int(AESConst.invShift[fpos])
    return (round, byte)
}

func columnSlice(wb: AttackTarget, pt: [UInt8], vref: [UInt8], col: Int, alpha: Int, perms: [Encoding16], reverseMC: Bool, faultAt: (Int) -> (Int, Int)) throws -> [[UInt8]] {
    var jobs: [Job] = []
    jobs.reserveCapacity(16 * alpha)
    for pos in 0..<16 {
        let (fr, fb) = faultAt(pos)
        for fval in 1...alpha {
            jobs.append(Job.pack(pt, faultRound: fr, byte: UInt8(fb), xor: UInt8(fval)))
        }
    }
    let raw = try wb.evalJobs(jobs)
    for pos in 0..<16 {
        var cols = [Array(vref[col * 4..<col * 4 + 4])]
        var ok = true
        for fval in 1...alpha {
            let idx = (pos * alpha + (fval - 1)) * 16
            let view = attackView(Array(raw[idx..<idx + 16]), encryptWB: wb.isEncrypt, outputF: perms, reverseMC: reverseMC)
            let diff = (0..<16).filter { view[$0] != vref[$0] }
            guard diff.count == 4 else {
                if fval == 1 { ok = false; break }
                throw AttackError.fail("fault diffusion changed")
            }
            let fcol = diff[0] / 4
            if diff != [fcol * 4, fcol * 4 + 1, fcol * 4 + 2, fcol * 4 + 3] || fcol != col {
                if fval == 1 { ok = false; break }
                throw AttackError.fail("fault column changed")
            }
            cols.append(Array(view[col * 4..<col * 4 + 4]))
        }
        if ok { return cols }
    }
    throw AttackError.fail("no fault position affects column \(col)")
}

func randomPlaintext(_ wb: AttackTarget, _ n: Int, _ rng: inout SplitMix64) throws -> [UInt8] {
    if wb.hasRandomInput { return try wb.getRandomInput(n) }
    return rng.bytes(16)
}

func step4(_ wb: AttackTarget, _ gtilde: Encoding16, _ gbarInv: Encoding16, _ C: [UInt8], _ mref: [UInt8], _ lastMC: Bool, _ rng: inout SplitMix64) throws -> ([UInt8], [UInt8]) {
    let perm = Encoding16.affine(alpha: C, beta: [UInt8](repeating: 0, count: 16)).combine(gbarInv).combine(gtilde)
    let alpha = 16
    let mid = 4
    let prep = faultAt4(col: 0, pos: 0, nr: wb.nr, encrypt: wb.isEncrypt, lastMC: lastMC).0
    try wb.prepareFaultRound(fround: prep, outputF: [perm], reverseMC: true)
    var lambdas: [[UInt8]] = []
    var betas: [[UInt8]] = []
    let refPT = mref
    let vref = attackView(try wb.applyRaw(refPT), encryptWB: wb.isEncrypt, outputF: [perm], reverseMC: true)
    for col in 0..<4 {
        var solved: (Bool, [UInt8], [UInt8]) = (false, [], [])
        for attempt in 0..<10 {
            let pt = attempt == 0 ? refPT : try randomPlaintext(wb, attempt, &rng)
            let view = attempt == 0 ? vref : attackView(try wb.applyRaw(pt), encryptWB: wb.isEncrypt, outputF: [perm], reverseMC: true)
            let fault = try columnSlice(wb: wb, pt: pt, vref: view, col: col, alpha: alpha, perms: [perm], reverseMC: true) { pos in
                faultAt4(col: col, pos: pos, nr: wb.nr, encrypt: wb.isEncrypt, lastMC: lastMC)
            }
            let limited = col == 0 ? nil : lambdas[0]
            solved = meet(col: col, fault: fault, midalpha: mid, encrypt: wb.isEncrypt, limited: limited)
            if solved.0 { break }
        }
        if !solved.0 { throw AttackError.fail("step4: failed to extract lambda/beta for column \(col)") }
        lambdas.append(solved.1)
        betas.append(solved.2)
    }
    let joined = lambdas[0] + lambdas[1] + lambdas[2] + lambdas[3]
    let shifted = wb.isEncrypt ? shiftRow(joined) : invShiftRow(joined)
    for x in 0..<16 where shifted[x] != shifted[x - (x % 4)] {
        throw AttackError.fail("step4: lambda disagrees inside a column")
    }
    return (joined, betas[0] + betas[1] + betas[2] + betas[3])
}

func permRound(lambda: [UInt8], beta: [UInt8], encrypt: Bool) -> Encoding16 {
    var enc = [[UInt8]]()
    enc.reserveCapacity(16)
    for b in 0..<16 {
        var t = [UInt8](repeating: 0, count: 256)
        for x in 0..<256 {
            let y = gmul(lambda[b], UInt8(x)) ^ beta[b]
            t[x] = encrypt ? AESConst.invSbox[Int(y)] : AESConst.sbox[Int(y)]
        }
        enc.append(t)
    }
    return Encoding16(enc: enc)
}

func keyPerm(_ keyPart: [UInt8], encrypt: Bool) -> Encoding16 {
    let beta = encrypt ? invShiftRow(invMixColumns(keyPart)) : shiftRow(keyPart)
    return permRound(lambda: [UInt8](repeating: 1, count: 16), beta: beta, encrypt: encrypt)
}

func step5(_ wb: AttackTarget, _ gtilde: Encoding16, _ gbarInv: Encoding16, _ C: [UInt8], _ lambda: [UInt8], _ beta: [UInt8], _ mref: [UInt8], _ lastMC: Bool, allRound: Bool, _ rng: inout SplitMix64) throws -> [[UInt8]] {
    var nround = wb.nr - (lastMC ? 3 : 4)
    if !lastMC { nround += 1 }
    if !allRound { nround = wb.nr == 10 ? 1 : 2 }
    var perms = [
        Encoding16.affine(alpha: C, beta: [UInt8](repeating: 0, count: 16)).combine(gbarInv).combine(gtilde),
        permRound(lambda: lambda, beta: beta, encrypt: wb.isEncrypt),
    ]
    var keys: [[UInt8]] = []
    let alpha = 16
    let mid = 4
    let fixed = [UInt8](repeating: 1, count: 4)
    for roundN in 0..<nround {
        let prep = faultAt5(col: 0, pos: 0, roundN: roundN, nr: wb.nr, encrypt: wb.isEncrypt, lastMC: lastMC).0
        try wb.prepareFaultRound(fround: prep, outputF: perms, reverseMC: true)
        var betas: [[UInt8]] = []
        for col in 0..<4 {
            var ok = false
            var betaCol: [UInt8] = []
            for attempt in 0..<10 {
                let pt = attempt == 0 ? mref : try randomPlaintext(wb, attempt, &rng)
                let view = attackView(try wb.applyRaw(pt), encryptWB: wb.isEncrypt, outputF: perms, reverseMC: true)
                let fault = try columnSlice(wb: wb, pt: pt, vref: view, col: col, alpha: alpha, perms: perms, reverseMC: true) { pos in
                    faultAt5(col: col, pos: pos, roundN: roundN, nr: wb.nr, encrypt: wb.isEncrypt, lastMC: lastMC)
                }
                let solved = meet(col: col, fault: fault, midalpha: mid, encrypt: wb.isEncrypt, limited: fixed)
                if solved.0 {
                    ok = true
                    betaCol = solved.2
                    break
                }
            }
            if !ok { throw AttackError.fail("step5: failed column \(col) of round offset \(roundN)") }
            betas.append(betaCol)
        }
        let betaRound = betas[0] + betas[1] + betas[2] + betas[3]
        let rkey = wb.isEncrypt ? mixColumns(shiftRow(betaRound)) : invShiftRow(betaRound)
        keys.append(rkey)
        perms.append(keyPerm(rkey, encrypt: wb.isEncrypt))
    }
    return keys
}

func assembleKey(_ wb: AttackTarget, _ keyPart: [[UInt8]], forceOffset: Int? = nil) throws -> [UInt8] {
    let keyLen = [10: 16, 12: 24, 14: 32][wb.nr] ?? 16
    var buf: [UInt8] = []
    var first: Int
    if wb.isEncrypt {
        first = wb.nr - 1 - keyPart.count
        for k in keyPart.reversed() { buf.append(contentsOf: k) }
    } else {
        first = 2
        for k in keyPart { buf.append(contentsOf: k) }
    }
    if let forceOffset { first = forceOffset }
    guard buf.count >= keyLen else { throw AttackError.fail("not enough round key material") }
    var key: [UInt8]?
    // DarkPhoenix steps the window by one round key (16 bytes), not by keyLen.
    for index in 0..<(buf.count / keyLen) {
        let start = index * 16
        guard start + keyLen <= buf.count else { break }
        let slice = Array(buf[start..<start + keyLen])
        let got = revertKey(slice, roundN: index + first)
        Log.v("revert slice \(index) round \(index + first): \(hex(got))")
        if let prev = key, prev != got {
            throw AttackError.fail("round keys do not revert to the same AES key (slice \(index) round \(index + first): \(hex(got)) vs \(hex(prev)))")
        }
        key = got
    }
    return key ?? []
}

func externalEncodings(_ wb: AttackTarget, _ gtilde: Encoding16, _ gbarInv: Encoding16, _ C: [UInt8], _ lambda: [UInt8], _ beta: [UInt8], _ key: [UInt8]) throws -> (input: Encoding16, output: Encoding16) {
    let first = Encoding16.affine(alpha: C, beta: [UInt8](repeating: 0, count: 16)).combine(gbarInv).combine(gtilde)
    let lambdaBeta = permRound(lambda: lambda, beta: beta, encrypt: wb.isEncrypt)
    let expanded = expandKey(key, rounds: wb.nr)
    let rkLast = roundKey(expanded, wb.nr)
    let rkPrev = roundKey(expanded, wb.nr - 1)
    let rk0 = roundKey(expanded, 0)
    let rk1 = roundKey(expanded, 1)
    var outTab = [[UInt8?]](repeating: [UInt8?](repeating: nil, count: 256), count: 16)
    for i in 0..<256 {
        let block = [UInt8](repeating: UInt8(i), count: 16)
        let mid = applyPermut(first, lambdaBeta, block, wb.isEncrypt)
        let d = wb.isEncrypt ? applyLastRoundEnc(mid, rkPrev, rkLast) : applyLastRoundDec(mid, rk0, rk1)
        for index in 0..<16 {
            if outTab[index][Int(d[index])] != nil { throw AttackError.fail("output encoding collision") }
            outTab[index][Int(d[index])] = UInt8(i)
        }
    }
    let output = Encoding16(enc: outTab.map { row in row.map { $0 ?? 0 } })
    var inTab = [[UInt8?]](repeating: [UInt8?](repeating: nil, count: 256), count: 16)
    for i in 0..<256 {
        let pt = [UInt8](repeating: UInt8(i), count: 16)
        let raw = try wb.applyRaw(pt)
        let decoded = output.decode(raw)
        let d = wb.isEncrypt ? aesDecryptBlock(decoded, expanded, wb.nr) : aesEncryptBlock(decoded, expanded, wb.nr)
        for index in 0..<16 {
            if inTab[index][Int(d[index])] != nil { throw AttackError.fail("input encoding collision") }
            inTab[index][Int(d[index])] = UInt8(i)
        }
    }
    let input = Encoding16(enc: inTab.map { row in row.map { $0 ?? 0 } })
    return (input, output)
}

func applyPermut(_ first: Encoding16, _ lambdaBeta: Encoding16, _ data: [UInt8], _ encrypt: Bool) -> [UInt8] {
    if encrypt {
        return lambdaBeta.encode(invShiftRow(invMixColumns(first.encode(invShiftRow(data)))))
    }
    return lambdaBeta.encode(shiftRow(mixColumns(first.encode(shiftRow(data)))))
}

func applyLastRoundEnc(_ data: [UInt8], _ rkPrev: [UInt8], _ rkLast: [UInt8]) -> [UInt8] {
    var s = shiftRow(subBytes(data))
    s = mixColumns(s)
    s = xorBytes(s, rkPrev)
    s = shiftRow(subBytes(s))
    return xorBytes(s, rkLast)
}

func applyLastRoundDec(_ data: [UInt8], _ rk0: [UInt8], _ rk1: [UInt8]) -> [UInt8] {
    var s = invSubBytes(invShiftRow(data))
    s = xorBytes(s, rk1)
    s = invMixColumns(s)
    s = invSubBytes(invShiftRow(s))
    return xorBytes(s, rk0)
}

func verifyEncodings(_ wb: AttackTarget, _ input: Encoding16, _ output: Encoding16, _ key: [UInt8]) throws {
    let expanded = expandKey(key, rounds: wb.nr)
    var rng = SplitMix64(state: 0xA11CE)
    for _ in 0..<4 {
        let pt = rng.bytes(16)
        let raw = try wb.applyRaw(pt)
        let decoded = output.decode(raw)
        let inner = wb.isEncrypt ? aesDecryptBlock(decoded, expanded, wb.nr) : aesEncryptBlock(decoded, expanded, wb.nr)
        for i in 0..<16 where input.enc[i][Int(inner[i])] != pt[i] {
            throw AttackError.fail("external encoding does not round-trip at byte \(i)")
        }
    }
}

func jsonInts1(_ any: Any?) -> [Int]? {
    guard let row = any as? [Any] else { return nil }
    return row.compactMap { ($0 as? NSNumber)?.intValue }
}

func jsonInts2(_ any: Any?) -> [[Int]]? {
    guard let rows = any as? [Any] else { return nil }
    return rows.compactMap { jsonInts1($0) }
}

func printRoundKeys(_ keys: [[UInt8]], nr: Int, encrypt: Bool) {
    if encrypt {
        let offset = nr - 2
        for (index, key) in keys.enumerated().reversed() {
            print(String(format: "k%02d: \(hex(key))", offset - index))
        }
    } else {
        for (index, key) in keys.enumerated() {
            print(String(format: "k%02d: \(hex(key))", index + 2))
        }
    }
}

struct Checkpoint {
    var state = 0
    var haveMref = false
    var mref = [UInt8](repeating: 0, count: 16)
    var rs: [[Int]] = []
    var M: [[UInt8]] = []
    var gtilde = Encoding16(enc: [])
    var gbarInv = Encoding16(enc: [])
    var roundShift: [Int] = []
    var C: [UInt8] = []
    var lambda: [UInt8] = []
    var beta: [UInt8] = []
    var keyPart: [[UInt8]] = []

    func save(_ path: String?) throws {
        guard let path else { return }
        let obj: [String: Any] = [
            "State": state,
            "Mref": hex(mref),
            "r_s": rs,
            "M": M.map { flat -> [String] in
                (0..<256).map { i in hex(Array(flat[i * 16..<(i + 1) * 16])) }
            },
            "gtilde_inv": gtilde.enc,
            "Gbar_inv": gbarInv.enc,
            "roundShift": roundShift,
            "C": C.map { Int($0) },
            "lambdaCol": lambda.map { Int($0) },
            "betaCol": beta.map { Int($0) },
            "keyPart": keyPart.map { $0.map { Int($0) } },
        ]
        let data = try JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: URL(fileURLWithPath: path))
    }

    static func load(_ path: String) throws -> Checkpoint {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        var cp = Checkpoint()
        cp.state = obj["State"] as? Int ?? 0
        if let hexM = obj["Mref"] as? String, let bytes = unhex(hexM), bytes.count == 16 {
            cp.mref = bytes
            cp.haveMref = true
        }
        if let rs = jsonInts2(obj["r_s"]) { cp.rs = rs }
        if let rows = obj["M"] as? [[String]] {
            cp.M = try rows.map { list in
                var flat = [UInt8]()
                flat.reserveCapacity(list.count * 16)
                for h in list {
                    guard let b = unhex(h), b.count == 16 else { throw AttackError.fail("bad plaintext in backup") }
                    flat.append(contentsOf: b)
                }
                return flat
            }
        }
        if let t = jsonInts2(obj["gtilde_inv"]), !t.isEmpty { cp.gtilde = Encoding16(enc: t.map { $0.map { UInt8(truncatingIfNeeded: $0) } }) }
        if let t = jsonInts2(obj["Gbar_inv"]), !t.isEmpty { cp.gbarInv = Encoding16(enc: t.map { $0.map { UInt8(truncatingIfNeeded: $0) } }) }
        if let v = jsonInts1(obj["roundShift"]) { cp.roundShift = v }
        if let v = jsonInts1(obj["C"]) { cp.C = v.map { UInt8(truncatingIfNeeded: $0) } }
        if let v = jsonInts1(obj["lambdaCol"]) { cp.lambda = v.map { UInt8(truncatingIfNeeded: $0) } }
        if let v = jsonInts1(obj["betaCol"]) { cp.beta = v.map { UInt8(truncatingIfNeeded: $0) } }
        if let v = jsonInts2(obj["keyPart"]) { cp.keyPart = v.map { $0.map { UInt8(truncatingIfNeeded: $0) } } }
        return cp
    }
}
