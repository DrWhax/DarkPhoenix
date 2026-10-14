// Metal port of DarkPhoenix (Apache-2.0). AES, encodings, and the encoded whitebox.
import Foundation

enum Log {
    static var verbose = false
    static var quiet = false
    static func v(_ s: @autoclosure () -> String) {
        if verbose { print(s()) }
    }
    static func progress(_ s: String) {
        if !quiet { print(s) }
    }
}

func mono() -> UInt64 { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) }
func elapsedMS(_ a: UInt64, _ b: UInt64) -> Double { Double(b &- a) / 1e6 }

func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
func unhex(_ s: String) -> [UInt8]? {
    let t = s.trimmingCharacters(in: .whitespaces)
    guard t.count % 2 == 0, !t.isEmpty else { return nil }
    var o = [UInt8]()
    o.reserveCapacity(t.count / 2)
    var i = t.startIndex
    while i < t.endIndex {
        let j = t.index(i, offsetBy: 2)
        guard let v = UInt8(t[i..<j], radix: 16) else { return nil }
        o.append(v)
        i = j
    }
    return o
}

@inline(__always) func xtime(_ a: UInt8) -> UInt8 {
    let hi = a & 0x80
    return (a << 1) ^ (hi != 0 ? 0x1b : 0)
}

@inline(__always) func gmul(_ a: UInt8, _ b: UInt8) -> UInt8 {
    var x = a, y = b, r: UInt8 = 0
    while y != 0 {
        if y & 1 != 0 { r ^= x }
        x = xtime(x)
        y >>= 1
    }
    return r
}

func gfInv(_ a: UInt8) -> UInt8 {
    if a == 0 { return 0 }
    var r: UInt8 = 1
    var b = a
    var e = 254
    while e > 0 {
        if e & 1 == 1 { r = gmul(r, b) }
        b = gmul(b, b)
        e >>= 1
    }
    return r
}

enum AESConst {
    static let shift: [UInt8] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
    static let invShift: [UInt8] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
    static let sbox: [UInt8] = {
        var s = [UInt8](repeating: 0, count: 256)
        for i in 0..<256 {
            let inv = gfInv(UInt8(i))
            var y = inv
            var r = inv
            for _ in 0..<4 {
                y = (y << 1) | (y >> 7)
                r ^= y
            }
            s[i] = r ^ 0x63
        }
        return s
    }()
    static let invSbox: [UInt8] = {
        var s = [UInt8](repeating: 0, count: 256)
        for i in 0..<256 { s[Int(sbox[i])] = UInt8(i) }
        return s
    }()
    static let mul2: [UInt8] = (0..<256).map { xtime(UInt8($0)) }
    static let mul3: [UInt8] = (0..<256).map { xtime(UInt8($0)) ^ UInt8($0) }
    static let mul9: [UInt8] = (0..<256).map { gmul(9, UInt8($0)) }
    static let mul11: [UInt8] = (0..<256).map { gmul(11, UInt8($0)) }
    static let mul13: [UInt8] = (0..<256).map { gmul(13, UInt8($0)) }
    static let mul14: [UInt8] = (0..<256).map { gmul(14, UInt8($0)) }
    static let rcon: [UInt8] = {
        var r = [UInt8](repeating: 0, count: 32)
        r[1] = 1
        for i in 2..<32 { r[i] = xtime(r[i - 1]) }
        return r
    }()

    static func mulTablesFlat() -> [UInt8] {
        mul2 + mul3 + mul9 + mul11 + mul13 + mul14
    }
}

func shiftRow(_ s: [UInt8]) -> [UInt8] {
    AESConst.shift.map { s[Int($0)] }
}
func invShiftRow(_ s: [UInt8]) -> [UInt8] {
    AESConst.invShift.map { s[Int($0)] }
}
func xorBytes(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
    zip(a, b).map { $0 ^ $1 }
}

func mixColumns(_ s: [UInt8]) -> [UInt8] {
    var o = [UInt8](repeating: 0, count: 16)
    for c in 0..<4 {
        let i = c * 4
        let a = s[i], b = s[i + 1], d = s[i + 2], e = s[i + 3]
        o[i] = AESConst.mul2[Int(a)] ^ AESConst.mul3[Int(b)] ^ d ^ e
        o[i + 1] = a ^ AESConst.mul2[Int(b)] ^ AESConst.mul3[Int(d)] ^ e
        o[i + 2] = a ^ b ^ AESConst.mul2[Int(d)] ^ AESConst.mul3[Int(e)]
        o[i + 3] = AESConst.mul3[Int(a)] ^ b ^ d ^ AESConst.mul2[Int(e)]
    }
    return o
}

func invMixColumns(_ s: [UInt8]) -> [UInt8] {
    var o = [UInt8](repeating: 0, count: 16)
    for c in 0..<4 {
        let i = c * 4
        let a = s[i], b = s[i + 1], d = s[i + 2], e = s[i + 3]
        o[i] = AESConst.mul14[Int(a)] ^ AESConst.mul11[Int(b)] ^ AESConst.mul13[Int(d)] ^ AESConst.mul9[Int(e)]
        o[i + 1] = AESConst.mul9[Int(a)] ^ AESConst.mul14[Int(b)] ^ AESConst.mul11[Int(d)] ^ AESConst.mul13[Int(e)]
        o[i + 2] = AESConst.mul13[Int(a)] ^ AESConst.mul9[Int(b)] ^ AESConst.mul14[Int(d)] ^ AESConst.mul11[Int(e)]
        o[i + 3] = AESConst.mul11[Int(a)] ^ AESConst.mul13[Int(b)] ^ AESConst.mul9[Int(d)] ^ AESConst.mul14[Int(e)]
    }
    return o
}

func subBytes(_ s: [UInt8]) -> [UInt8] { s.map { AESConst.sbox[Int($0)] } }
func invSubBytes(_ s: [UInt8]) -> [UInt8] { s.map { AESConst.invSbox[Int($0)] } }

func expandKey(_ key: [UInt8], rounds: Int) -> [UInt8] {
    let keySize = key.count / 4
    var ext = key
    let words = (rounds + 1) * 4
    var i = keySize
    while i < words {
        var t = Array(ext[(i - 1) * 4..<i * 4])
        let t2 = Array(ext[(i - keySize) * 4..<(i - keySize + 1) * 4])
        if i % keySize == 0 {
            t = [AESConst.sbox[Int(t[1])], AESConst.sbox[Int(t[2])], AESConst.sbox[Int(t[3])], AESConst.sbox[Int(t[0])]]
            t[0] ^= AESConst.rcon[i / keySize]
        } else if keySize == 8 && (i % 4) == 0 {
            t = t.map { AESConst.sbox[Int($0)] }
        }
        for j in 0..<4 { ext.append(t[j] ^ t2[j]) }
        i += 1
    }
    return ext
}

func revertKey(_ rkey: [UInt8], roundN: Int) -> [UInt8] {
    let keySize = rkey.count / 4
    var ext = rkey
    var i = (roundN * 4) + keySize - 1
    while i >= keySize {
        var t = Array(ext[(keySize - 2) * 4..<(keySize - 1) * 4])
        let t2 = Array(ext[(keySize - 1) * 4..<keySize * 4])
        if i % keySize == 0 {
            t = [AESConst.sbox[Int(t[1])], AESConst.sbox[Int(t[2])], AESConst.sbox[Int(t[3])], AESConst.sbox[Int(t[0])]]
            t[0] ^= AESConst.rcon[i / keySize]
        } else if keySize == 8 && (i % 4) == 0 {
            t = t.map { AESConst.sbox[Int($0)] }
        }
        var prev = [UInt8](repeating: 0, count: 4)
        for j in 0..<4 { prev[j] = t[j] ^ t2[j] }
        ext = prev + Array(ext[0..<(keySize - 1) * 4])
        i -= 1
    }
    return Array(ext[0..<keySize * 4])
}

func roundKey(_ expanded: [UInt8], _ i: Int) -> [UInt8] {
    Array(expanded[i * 16..<(i + 1) * 16])
}

struct SplitMix64 {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }
    mutating func byte() -> UInt8 { UInt8(truncatingIfNeeded: next()) }
    mutating func below(_ n: Int) -> Int { Int(next() % UInt64(n)) }
    mutating func bytes(_ n: Int) -> [UInt8] { (0..<n).map { _ in byte() } }
    mutating func shuffle(_ a: inout [UInt8]) {
        if a.count < 2 { return }
        for i in stride(from: a.count - 1, through: 1, by: -1) {
            let j = below(i + 1)
            a.swapAt(i, j)
        }
    }
}

struct Encoding16 {
    var enc: [[UInt8]] // [byte][x] -> encode(x)

    static func identity() -> Encoding16 {
        Encoding16(enc: (0..<16).map { _ in Array(UInt8(0)...UInt8(255)) })
    }

    static func random(_ rng: inout SplitMix64) -> Encoding16 {
        var tables = [[UInt8]]()
        tables.reserveCapacity(16)
        for _ in 0..<16 {
            var p = Array(UInt8(0)...UInt8(255))
            rng.shuffle(&p)
            tables.append(p)
        }
        return Encoding16(enc: tables)
    }

    static func affine(alpha: [UInt8], beta: [UInt8]) -> Encoding16 {
        var tables = [[UInt8]]()
        for b in 0..<16 {
            var t = [UInt8](repeating: 0, count: 256)
            let al = alpha[b], be = beta[b]
            for x in 0..<256 { t[x] = gmul(al, UInt8(x)) ^ be }
            tables.append(t)
        }
        return Encoding16(enc: tables)
    }

    func encode(_ data: [UInt8]) -> [UInt8] {
        (0..<16).map { enc[$0][Int(data[$0])] }
    }

    func decodeTable() -> [[UInt8]] {
        enc.map { table in
            var d = [UInt8](repeating: 0, count: 256)
            for i in 0..<256 { d[Int(table[i])] = UInt8(i) }
            return d
        }
    }

    func decode(_ data: [UInt8]) -> [UInt8] {
        let d = decodeTable()
        return (0..<16).map { d[$0][Int(data[$0])] }
    }

    func inverse() -> Encoding16 { Encoding16(enc: decodeTable()) }

    /// self ∘ other
    func combine(_ other: Encoding16) -> Encoding16 {
        var out = [[UInt8]]()
        out.reserveCapacity(16)
        for b in 0..<16 {
            out.append(other.enc[b].map { self.enc[b][Int($0)] })
        }
        return Encoding16(enc: out)
    }

    func flatEncode() -> [UInt8] { enc.flatMap { $0 } }
    func flatDecode() -> [UInt8] { decodeTable().flatMap { $0 } }
}

/// Packed job shared with the Metal shader. 20 bytes, little-endian words.
struct Job {
    var w0: UInt32 = 0
    var w1: UInt32 = 0
    var w2: UInt32 = 0
    var w3: UInt32 = 0
    var meta: UInt32 = 0xFFFF

    static func pack(_ block: [UInt8], faultRound: Int?, byte: UInt8, xor: UInt8) -> Job {
        func word(_ i: Int) -> UInt32 {
            UInt32(block[i]) | (UInt32(block[i + 1]) << 8) | (UInt32(block[i + 2]) << 16) | (UInt32(block[i + 3]) << 24)
        }
        var j = Job()
        j.w0 = word(0); j.w1 = word(4); j.w2 = word(8); j.w3 = word(12)
        let fr: UInt32 = faultRound.map { UInt32($0) } ?? 0xFFFF
        j.meta = fr | (UInt32(byte) << 16) | (UInt32(xor) << 24)
        return j
    }

    func faultRound() -> Int? {
        let fr = meta & 0xFFFF
        return fr == 0xFFFF ? nil : Int(fr)
    }
    func faultByte() -> UInt8 { UInt8((meta >> 16) & 0xFF) }
    func faultXor() -> UInt8 { UInt8((meta >> 24) & 0xFF) }
}

func loadJob(_ job: Job, _ s: UnsafeMutablePointer<UInt8>) {
    let w = [job.w0, job.w1, job.w2, job.w3]
    for i in 0..<4 {
        s[i * 4] = UInt8(truncatingIfNeeded: w[i])
        s[i * 4 + 1] = UInt8(truncatingIfNeeded: w[i] >> 8)
        s[i * 4 + 2] = UInt8(truncatingIfNeeded: w[i] >> 16)
        s[i * 4 + 3] = UInt8(truncatingIfNeeded: w[i] >> 24)
    }
}

func storeBlock(_ s: UnsafePointer<UInt8>) -> [UInt8] {
    (0..<16).map { s[$0] }
}

enum Step1Layout {
    static let rsCount = 3
    static let slotCount = 16 * rsCount * 256
    static func slot(byte: Int, rs: Int, value: Int) -> Int {
        (byte * rsCount + rs) * 256 + value
    }
}

let RSPairs: [(Int, Int, Int, Int)] = [(0, 1, 2, 3), (0, 2, 3, 1), (0, 3, 1, 2)]

func postShift(_ s: [UInt8], encryptWB: Bool) -> [UInt8] {
    encryptWB ? invShiftRow(s) : shiftRow(s)
}

func attackView(_ raw: [UInt8], encryptWB: Bool, outputF: [Encoding16], reverseMC: Bool) -> [UInt8] {
    var data = postShift(raw, encryptWB: encryptWB)
    if outputF.isEmpty { return data }
    for (num, perm) in outputF.enumerated() {
        data = perm.encode(data)
        if reverseMC || num < outputF.count - 1 {
            if encryptWB {
                data = invShiftRow(invMixColumns(data))
            } else {
                data = shiftRow(mixColumns(data))
            }
        }
    }
    return data
}

struct AttackError: Error, CustomStringConvertible {
    let message: String
    var description: String { message }
    static func fail(_ m: String) -> AttackError { AttackError(message: m) }
}

/// Encoded AES whitebox matching darkphoenixAES.test.AESEncoded + the fast fault path.
final class Whitebox {
    let nr: Int
    let key: [UInt8]
    let isEncrypt: Bool
    let roundKeys: [UInt8]
    let encTab: [UInt8]   // (nr+1)*16*256 encode
    let decTab: [UInt8]
    let roundPerm: [UInt8] // nr*16
    let revPerm: [UInt8]
    let identity: Bool
    var forceCPU: Bool
    var engine: MetalEngine?

    init(key: [UInt8], encrypt: Bool, seed: UInt64, identity: Bool, forceCPU: Bool) throws {
        let rounds = [16: 10, 24: 12, 32: 14][key.count]
        guard let rounds else { throw AttackError.fail("key length must be 16, 24, or 32") }
        self.nr = rounds
        self.key = key
        self.isEncrypt = encrypt
        self.identity = identity
        self.forceCPU = forceCPU
        self.roundKeys = expandKey(key, rounds: rounds)

        var rng = SplitMix64(state: seed == 0 ? 0xC0FFEE : seed)
        var enc = [UInt8]()
        var dec = [UInt8]()
        enc.reserveCapacity((rounds + 1) * 16 * 256)
        dec.reserveCapacity((rounds + 1) * 16 * 256)
        var rperm = [UInt8]()
        var rev = [UInt8]()
        for _ in 0...rounds {
            let e = identity ? Encoding16.identity() : Encoding16.random(&rng)
            enc.append(contentsOf: e.flatEncode())
            dec.append(contentsOf: e.flatDecode())
        }
        for _ in 0..<rounds {
            var p = Array(UInt8(0)..<UInt8(16))
            if !identity { rng.shuffle(&p) }
            rperm.append(contentsOf: p)
            var inv = [UInt8](repeating: 0, count: 16)
            for i in 0..<16 { inv[Int(p[i])] = UInt8(i) }
            rev.append(contentsOf: inv)
        }
        self.encTab = enc
        self.decTab = dec
        self.roundPerm = rperm
        self.revPerm = rev
        self.engine = nil
        if !forceCPU {
            self.engine = try MetalEngine(nr: rounds, roundKeys: self.roundKeys, encTab: enc, decTab: dec, roundPerm: rperm, revPerm: rev)
        }
    }

    func applyRaw(_ block: [UInt8]) throws -> [UInt8] {
        try evalJobs([Job.pack(block, faultRound: nil, byte: 0, xor: 0)])
    }

    func applyReverseRaw(_ block: [UInt8]) throws -> [UInt8] {
        // Opposite direction, no fault. Implemented on CPU (510 calls in step 1).
        var s = block
        return s.withUnsafeMutableBufferPointer { buf -> [UInt8] in
            cpuForward(buf.baseAddress!, faultRound: nil, faultByte: 0, faultXor: 0, encrypt: !isEncrypt)
            return Array(buf)
        }
    }

    func applyFaultRaw(_ block: [UInt8], round: Int, byte: Int, xor: UInt8) throws -> [UInt8] {
        try evalJobs([Job.pack(block, faultRound: round, byte: UInt8(byte), xor: xor)])
    }

    func evalJobs(_ jobs: [Job]) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: jobs.count * 16)
        try jobs.withUnsafeBufferPointer { jp in
            try out.withUnsafeMutableBufferPointer { op in
                try evalJobsPtr(jp.baseAddress!, jobs.count, op.baseAddress!)
            }
        }
        return out
    }

    func evalJobsPtr(_ jobs: UnsafePointer<Job>, _ n: Int, _ out: UnsafeMutablePointer<UInt8>) throws {
        if let engine, !forceCPU {
            try engine.eval(jobs, n, out, encrypt: isEncrypt)
        } else {
            for i in 0..<n {
                loadJob(jobs[i], out + i * 16)
                cpuForward(out + i * 16, faultRound: jobs[i].faultRound(), faultByte: jobs[i].faultByte(), faultXor: jobs[i].faultXor(), encrypt: isEncrypt)
            }
        }
    }

    func step2(_ plains: [UInt8], faultRound: Int, faultBytes: [UInt8]) throws -> [UInt8] {
        let n = 16 * 256 * 256
        var out = [UInt8](repeating: 0, count: n * 16)
        if let engine, !forceCPU {
            try plains.withUnsafeBufferPointer { pp in
                try faultBytes.withUnsafeBufferPointer { fb in
                    try out.withUnsafeMutableBufferPointer { op in
                        try engine.step2(pp.baseAddress!, fb.baseAddress!, faultRound: faultRound, encrypt: isEncrypt, out: op.baseAddress!)
                    }
                }
            }
        } else {
            out.withUnsafeMutableBufferPointer { op in
                plains.withUnsafeBufferPointer { pp in
                    for b in 0..<16 {
                        for xi in 0..<256 {
                            let src = (b * 256 + xi) * 16
                            for fval in 0..<256 {
                                let dst = ((b * 256 + xi) * 256 + fval) * 16
                                for i in 0..<16 { op[dst + i] = pp[src + i] }
                                let fr: Int? = fval == 0 ? nil : faultRound
                                let fx: UInt8 = fval == 0 ? 0 : UInt8(fval)
                                cpuForward(op.baseAddress! + dst, faultRound: fr, faultByte: faultBytes[b], faultXor: fx, encrypt: isEncrypt)
                                // attack view
                                var tmp = Array(UnsafeBufferPointer(start: op.baseAddress! + dst, count: 16))
                                tmp = postShift(tmp, encryptWB: isEncrypt)
                                for i in 0..<16 { op[dst + i] = tmp[i] }
                            }
                        }
                    }
                }
            }
        }
        return out
    }

    /// Fills persistent slot tables. Returns (flags, inputs) with Step1Layout.
    func searchStep1(mref: [UInt8], valueRef: [UInt8], doubleRS: Bool, maxTrials: Int) throws -> (flags: [UInt32], inputs: [UInt8]) {
        let slots = Step1Layout.slotCount
        var flags = [UInt32](repeating: 0, count: slots)
        var inputs = [UInt8](repeating: 0, count: slots * 16)
        for c in 0..<4 {
            for rs in 0..<3 {
                for row in 0..<4 {
                    let b = c * 4 + row
                    let v = Int(valueRef[b])
                    let sl = Step1Layout.slot(byte: b, rs: rs, value: v)
                    flags[sl] = 1
                    for i in 0..<16 { inputs[sl * 16 + i] = mref[i] }
                }
            }
        }
        let batch = 1 << 20
        var base: UInt64 = 0
        var trials = 0
        let t0 = mono()
        while !step1Done(flags) {
            if trials >= maxTrials {
                throw AttackError.fail("step1: gave up after \(trials) trials (double=\(doubleRS))")
            }
            let n = min(batch, maxTrials - trials)
            if let engine, !forceCPU {
                if trials == 0 { try engine.step1Reset(flags: flags, inputs: inputs) }
                flags = try engine.step1Run(base: base, count: n, valueRef: valueRef, doubleRS: doubleRS, encrypt: isEncrypt)
            } else {
                cpuStep1(base: base, count: n, valueRef: valueRef, doubleRS: doubleRS, flags: &flags, inputs: &inputs)
            }
            base += UInt64(n)
            trials += n
            if trials == n || step1Done(flags) || trials % (batch * 8) == 0 {
                let present = step1Present(flags)
                print(String(format: "  step1  %d trials  %d/4096 slots  %.0f ms", trials, present, elapsedMS(t0, mono())))
            }
        }
        if let engine, !forceCPU {
            inputs = try engine.copyStep1Inputs()
        }
        return (flags, inputs)
    }

    private func cpuForward(_ s: UnsafeMutablePointer<UInt8>, faultRound: Int?, faultByte: UInt8, faultXor: UInt8, encrypt: Bool) {
        if encrypt {
            applyTab(s, decTab, 0)
            for r in 0..<nr {
                if faultRound == r { inject(s, attackRound: r, fbyte: faultByte, fxor: faultXor, encrypt: true) }
                encRound(s, r)
            }
            applyTab(s, encTab, nr)
        } else {
            applyTab(s, decTab, nr)
            for ar in 0..<nr {
                let aesR = nr - 1 - ar
                if faultRound == ar { inject(s, attackRound: ar, fbyte: faultByte, fxor: faultXor, encrypt: false) }
                decRound(s, aesR)
            }
            applyTab(s, encTab, 0)
        }
    }

    private func applyTab(_ s: UnsafeMutablePointer<UInt8>, _ tab: [UInt8], _ round: Int) {
        tab.withUnsafeBufferPointer { tp in
            let base = tp.baseAddress!
            for i in 0..<16 {
                s[i] = base[(round * 16 + i) * 256 + Int(s[i])]
            }
        }
    }

    private func inject(_ s: UnsafeMutablePointer<UInt8>, attackRound: Int, fbyte: UInt8, fxor: UInt8, encrypt: Bool) {
        if encrypt {
            applyTab(s, encTab, attackRound)
            var pos = Int(fbyte)
            if attackRound != 0 { pos = Int(roundPerm[(attackRound - 1) * 16 + Int(fbyte)]) }
            s[pos] ^= fxor
            applyTab(s, decTab, attackRound)
        } else {
            let aesRound = nr - 1 - attackRound
            let encRound = aesRound + 1
            applyTab(s, encTab, encRound)
            var pos = Int(fbyte)
            if encRound != nr { pos = Int(revPerm[aesRound * 16 + Int(fbyte)]) }
            s[pos] ^= fxor
            applyTab(s, decTab, encRound)
        }
    }

    private func addRK(_ s: UnsafeMutablePointer<UInt8>, _ round: Int) {
        let off = round * 16
        for i in 0..<16 { s[i] ^= roundKeys[off + i] }
    }

    private func encRound(_ s: UnsafeMutablePointer<UInt8>, _ round: Int) {
        addRK(s, round)
        if round == nr - 1 {
            var t = [UInt8](repeating: 0, count: 16)
            for i in 0..<16 { t[i] = AESConst.sbox[Int(s[Int(AESConst.shift[i])])] }
            for i in 0..<16 { s[i] = t[i] }
            addRK(s, nr)
        } else {
            var t = [UInt8](repeating: 0, count: 16)
            for i in 0..<16 { t[i] = AESConst.sbox[Int(s[Int(AESConst.shift[i])])] }
            for c in 0..<4 {
                let i = c * 4
                let a = t[i], b = t[i + 1], d = t[i + 2], e = t[i + 3]
                s[i] = AESConst.mul2[Int(a)] ^ AESConst.mul3[Int(b)] ^ d ^ e
                s[i + 1] = a ^ AESConst.mul2[Int(b)] ^ AESConst.mul3[Int(d)] ^ e
                s[i + 2] = a ^ b ^ AESConst.mul2[Int(d)] ^ AESConst.mul3[Int(e)]
                s[i + 3] = AESConst.mul3[Int(a)] ^ b ^ d ^ AESConst.mul2[Int(e)]
            }
        }
    }

    private func decRound(_ s: UnsafeMutablePointer<UInt8>, _ round: Int) {
        if round == nr - 1 {
            addRK(s, nr)
            var t = [UInt8](repeating: 0, count: 16)
            for i in 0..<16 { t[i] = s[Int(AESConst.invShift[i])] }
            for i in 0..<16 { s[i] = AESConst.invSbox[Int(t[i])] }
            addRK(s, round)
        } else {
            var t = [UInt8](repeating: 0, count: 16)
            for c in 0..<4 {
                let i = c * 4
                let a = s[i], b = s[i + 1], d = s[i + 2], e = s[i + 3]
                t[i] = AESConst.mul14[Int(a)] ^ AESConst.mul11[Int(b)] ^ AESConst.mul13[Int(d)] ^ AESConst.mul9[Int(e)]
                t[i + 1] = AESConst.mul9[Int(a)] ^ AESConst.mul14[Int(b)] ^ AESConst.mul11[Int(d)] ^ AESConst.mul13[Int(e)]
                t[i + 2] = AESConst.mul13[Int(a)] ^ AESConst.mul9[Int(b)] ^ AESConst.mul14[Int(d)] ^ AESConst.mul11[Int(e)]
                t[i + 3] = AESConst.mul11[Int(a)] ^ AESConst.mul13[Int(b)] ^ AESConst.mul9[Int(d)] ^ AESConst.mul14[Int(e)]
            }
            var u = [UInt8](repeating: 0, count: 16)
            for i in 0..<16 { u[i] = t[Int(AESConst.invShift[i])] }
            for i in 0..<16 { s[i] = AESConst.invSbox[Int(u[i])] }
            addRK(s, round)
        }
    }

    private func cpuStep1(base: UInt64, count: Int, valueRef: [UInt8], doubleRS: Bool, flags: inout [UInt32], inputs: inout [UInt8]) {
        var block = [UInt8](repeating: 0, count: 16)
        for i in 0..<count {
            let v = base + UInt64(i)
            for k in 0..<16 { block[k] = 0 }
            var x = v
            for k in 0..<8 {
                block[15 - k] = UInt8(truncatingIfNeeded: x)
                x >>= 8
            }
            let saved = block
            block.withUnsafeMutableBufferPointer { buf in
                cpuForward(buf.baseAddress!, faultRound: nil, faultByte: 0, faultXor: 0, encrypt: isEncrypt)
            }
            var view = postShift(block, encryptWB: isEncrypt)
            considerStep1(&view, input: saved, valueRef: valueRef, doubleRS: doubleRS, flags: &flags, inputs: &inputs)
        }
    }
}

func step1Present(_ flags: [UInt32]) -> Int {
    var present = 0
    for b in 0..<16 {
        var best = 0
        for rs in 0..<3 {
            var n = 0
            let base = (b * 3 + rs) * 256
            for v in 0..<256 where flags[base + v] != 0 { n += 1 }
            if n > best { best = n }
        }
        present += best
    }
    return present
}

func step1Done(_ flags: [UInt32]) -> Bool {
    for b in 0..<16 {
        var ok = false
        for rs in 0..<3 {
            let base = (b * 3 + rs) * 256
            var n = 0
            for v in 0..<256 where flags[base + v] != 0 { n += 1 }
            if n == 256 { ok = true; break }
        }
        if !ok { return false }
    }
    return true
}

func considerStep1(_ value: inout [UInt8], input: [UInt8], valueRef: [UInt8], doubleRS: Bool, flags: inout [UInt32], inputs: inout [UInt8]) {
    for c in 0..<4 {
        for (rs, pair) in RSPairs.enumerated() {
            let a1 = c * 4 + pair.0, a2 = c * 4 + pair.1, b1 = c * 4 + pair.2, b2 = c * 4 + pair.3
            if doubleRS {
                if value[a1] == valueRef[a1] && value[a2] == valueRef[a2] {
                    claim(&flags, &inputs, byte: c * 4 + pair.2, rs: rs, value: Int(value[b1]), input: input)
                    claim(&flags, &inputs, byte: c * 4 + pair.3, rs: rs, value: Int(value[b2]), input: input)
                }
                if value[b1] == valueRef[b1] && value[b2] == valueRef[b2] {
                    claim(&flags, &inputs, byte: c * 4 + pair.0, rs: rs, value: Int(value[a1]), input: input)
                    claim(&flags, &inputs, byte: c * 4 + pair.1, rs: rs, value: Int(value[a2]), input: input)
                }
            } else {
                if value[a1] == valueRef[a1] { claim(&flags, &inputs, byte: c * 4 + pair.2, rs: rs, value: Int(value[b1]), input: input) }
                if value[a2] == valueRef[a2] { claim(&flags, &inputs, byte: c * 4 + pair.3, rs: rs, value: Int(value[b2]), input: input) }
                if value[b1] == valueRef[b1] { claim(&flags, &inputs, byte: c * 4 + pair.0, rs: rs, value: Int(value[a1]), input: input) }
                if value[b2] == valueRef[b2] { claim(&flags, &inputs, byte: c * 4 + pair.1, rs: rs, value: Int(value[a2]), input: input) }
            }
        }
    }
}

func claim(_ flags: inout [UInt32], _ inputs: inout [UInt8], byte: Int, rs: Int, value: Int, input: [UInt8]) {
    let sl = Step1Layout.slot(byte: byte, rs: rs, value: value)
    if flags[sl] != 0 { return }
    flags[sl] = 1
    for i in 0..<16 { inputs[sl * 16 + i] = input[i] }
}

func selectStep1(flags: [UInt32], inputs: [UInt8], doubleRS: Bool) throws -> (M: [[UInt8]], rs: [[Int]]) {
    var M = [[UInt8]]()
    var rsOut = [[Int]]()
    M.reserveCapacity(16)
    for col in 0..<4 {
        for row in 0..<4 {
            var found = false
            for (rsIndex, pair) in RSPairs.enumerated() {
                let b = col * 4 + row
                let base = Step1Layout.slot(byte: b, rs: rsIndex, value: 0)
                var complete = true
                for v in 0..<256 where flags[base + v] == 0 { complete = false; break }
                if !complete || found { continue }
                found = true
                var list = [UInt8]()
                list.reserveCapacity(256 * 16)
                for v in 0..<256 {
                    let off = (base + v) * 16
                    list.append(contentsOf: inputs[off..<off + 16])
                }
                M.append(list)
                var a1 = pair.0, a2 = pair.1, b1 = pair.2, b2 = pair.3
                if doubleRS {
                    if row == a1 || row == a2 { swap(&a1, &b1); swap(&a2, &b2) }
                    if row == a1 || row == a2 { throw AttackError.fail("step1: bad row index") }
                    rsOut.append([col * 4 + a1, col * 4 + a2])
                } else if row == a1 {
                    rsOut.append([col * 4 + b1])
                } else if row == a2 {
                    rsOut.append([col * 4 + b2])
                } else if row == b1 {
                    rsOut.append([col * 4 + a1])
                } else if row == b2 {
                    rsOut.append([col * 4 + a2])
                } else {
                    throw AttackError.fail("step1: bad row index")
                }
            }
            if !found { throw AttackError.fail("step1: incomplete column \(col) row \(row)") }
        }
    }
    return (M, rsOut)
}

func aesEncryptBlock(_ block: [UInt8], _ expanded: [UInt8], _ rounds: Int) -> [UInt8] {
    var s = block
    for r in 0..<rounds {
        for i in 0..<16 { s[i] ^= expanded[r * 16 + i] }
        if r == rounds - 1 {
            s = shiftRow(subBytes(s))
            for i in 0..<16 { s[i] ^= expanded[rounds * 16 + i] }
        } else {
            s = mixColumns(shiftRow(subBytes(s)))
        }
    }
    return s
}

func aesDecryptBlock(_ block: [UInt8], _ expanded: [UInt8], _ rounds: Int) -> [UInt8] {
    var s = block
    for r in stride(from: rounds - 1, through: 0, by: -1) {
        if r == rounds - 1 {
            for i in 0..<16 { s[i] ^= expanded[rounds * 16 + i] }
            s = invSubBytes(invShiftRow(s))
            for i in 0..<16 { s[i] ^= expanded[r * 16 + i] }
        } else {
            s = invMixColumns(s)
            s = invSubBytes(invShiftRow(s))
            for i in 0..<16 { s[i] ^= expanded[r * 16 + i] }
        }
    }
    return s
}
