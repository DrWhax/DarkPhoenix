import Foundation

struct Options {
    var selftest = false
    var key: [UInt8]?
    var seed: UInt64 = 0
    var bits = 128
    var encrypt = true
    var useReverse = true
    var doubleRS = false
    var cpu = false
    var encodings = false
    var identity = false
    var bench: Int?
    var verbose = false
    var oracle: String?
    var backup: String?
    var auto = false
    var retry = -1
    var forceOffset: Int?
    var partial = false
    var noProgress = false
}

func parse() -> Options {
    var o = Options()
    var args = Array(CommandLine.arguments.dropFirst())
    func take(_ name: String) -> String? {
        guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
        let v = args[i + 1]
        args.removeSubrange(i...i + 1)
        return v
    }
    if args.contains("-h") || args.contains("--help") {
        printUsage()
        exit(0)
    }
    o.selftest = args.contains("--selftest")
    o.encrypt = !args.contains("--decrypt")
    o.useReverse = !args.contains("--no-reverse")
    o.doubleRS = args.contains("--double")
    o.cpu = args.contains("--cpu")
    o.encodings = args.contains("--encodings") || o.selftest
    o.identity = args.contains("--identity")
    o.verbose = args.contains("--verbose")
    if let k = take("--key") { o.key = unhex(k) }
    if let s = take("--seed"), let v = UInt64(s) { o.seed = v }
    if let b = take("--bits"), let v = Int(b) { o.bits = v }
    if let n = take("--bench"), let v = Int(n) { o.bench = v }
    o.oracle = take("--oracle")
    o.backup = take("--backup")
    o.auto = args.contains("--auto")
    if let r = take("--retry"), let v = Int(r) { o.retry = v }
    if let r = take("--force-offset"), let v = Int(r) { o.forceOffset = v }
    o.partial = args.contains("--partial")
    o.noProgress = args.contains("--no-progress")
    return o
}

func attackConfig(_ opt: Options) -> AttackConfig {
    var c = AttackConfig()
    c.useReverse = opt.useReverse
    c.doubleRS = opt.doubleRS
    c.wantEncodings = opt.encodings
    c.allRound = !opt.partial
    c.forceOffset = opt.forceOffset
    c.backup = opt.backup
    c.auto = opt.auto
    c.retry = opt.retry
    return c
}

func printUsage() {
    print("""
    darkphoenix-metal — DarkPhoenix AES whitebox recovery

    Usage:
      darkphoenix-metal [--key HEX] [--seed N] [--bits 128|192|256]
                        [--decrypt] [--no-reverse] [--double] [--identity]
                        [--cpu] [--encodings] [--verbose] [--bench N]
      darkphoenix-metal --oracle 'python3 -u gpu/oracle.py encoded --key HEX --seed 1'
      darkphoenix-metal --oracle 'python3 -u gpu/oracle.py encoded --auto --key HEX --seed 1' --auto
      darkphoenix-metal --backup attack.json --oracle '...'
      darkphoenix-metal --selftest

    Without --oracle, the white-box is an encoded AES running on the GPU.
    With --oracle, apply/applyFault/applyReverse are performed by that process.
    See gpu/oracle.py to wrap a WhiteBoxedAES subclass. Sage is not required.
    """)
}

func runExternal(command: String, expected: [UInt8]?, config: AttackConfig) throws -> Recovery {
    let oracle = try ExternalOracle(command: command)
    defer { oracle.close() }
    print("oracle rounds=\(oracle.nr) \(oracle.isEncrypt ? "encrypt" : "decrypt") reverse=\(oracle.hasReverse) auto=\(oracle.isAuto) dynamic=\(oracle.isDynamic)")
    var cfg = config
    if config.useReverse && !oracle.hasReverse {
        print("oracle has no reverse; step 1 will search")
        cfg.useReverse = false
    }
    var rng = SplitMix64(state: UInt64.random(in: 1...UInt64.max))
    let rec = try recover(wb: oracle, mref: nil, config: cfg, rng: &rng)
    if let expected, rec.key != expected {
        throw AttackError.fail("recovered \(hex(rec.key)) != expected \(hex(expected))")
    }
    return rec
}

func nist() throws {
    let vectors: [(String, String, String)] = [
        ("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
        ("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "6bc1bee22e409f96e93d7e117393172a", "bd334f1d6e45f25ff712a214571fa5cc"),
        ("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"),
    ]
    guard AESConst.sbox[0] == 0x63, AESConst.sbox[1] == 0x7c else {
        throw AttackError.fail("AES S-box mismatch")
    }
    for (kh, ph, ch) in vectors {
        let key = unhex(kh)!, pt = unhex(ph)!, ct = unhex(ch)!
        let rounds = [16: 10, 24: 12, 32: 14][key.count]!
        let exp = expandKey(key, rounds: rounds)
        guard aesEncryptBlock(pt, exp, rounds) == ct else { throw AttackError.fail("NIST encrypt \(kh.prefix(8))") }
        guard aesDecryptBlock(ct, exp, rounds) == pt else { throw AttackError.fail("NIST decrypt \(kh.prefix(8))") }
        guard roundKey(exp, 0) == key || key.count != 16 else { throw AttackError.fail("round key 0") }
        for r in 0...rounds {
            let sliceStart = r * 16
            // revert the schedule word that begins this round key only when it is aligned to the cipher key.
            if key.count == 16 {
                let got = revertKey(roundKey(exp, r), roundN: r)
                if got != key { throw AttackError.fail("revertKey round \(r)") }
            }
            _ = sliceStart
        }
        if key.count != 16 {
            let words = key.count / 4
            for r in 0...2 {
                let start = r * 4 * 4
                let slice = Array(exp[start..<start + key.count])
                if revertKey(slice, roundN: r) != key { throw AttackError.fail("revertKey-\(key.count) round \(r)") }
            }
            _ = words
        }
    }
}

func checkOracle(_ wb: Whitebox) throws {
    var rng = SplitMix64(state: 99)
    let saved = wb.forceCPU
    for round in 0..<min(wb.nr, 4) {
        let pt = rng.bytes(16)
        let byte = rng.below(16)
        let x = UInt8(1 + rng.below(255))
        wb.forceCPU = true
        let c0 = try wb.applyRaw(pt)
        let c1 = try wb.applyFaultRaw(pt, round: round, byte: byte, xor: x)
        wb.forceCPU = false
        let g0 = try wb.applyRaw(pt)
        let g1 = try wb.applyFaultRaw(pt, round: round, byte: byte, xor: x)
        if c0 != g0 || c1 != g1 {
            wb.forceCPU = saved
            throw AttackError.fail("GPU/CPU mismatch at round \(round) byte \(byte)")
        }
    }
    wb.forceCPU = false
    for _ in 0..<4 {
        let pt = rng.bytes(16)
        let ct = try wb.applyRaw(pt)
        if try wb.applyReverseRaw(ct) != pt {
            wb.forceCPU = saved
            throw AttackError.fail("GPU forward is not inverted by the encoded AES reverse")
        }
    }
    wb.forceCPU = saved
}

func runOne(key: [UInt8], seed: UInt64, encrypt: Bool, reverse: Bool, doubleRS: Bool, identity: Bool, cpu: Bool, encodings: Bool, config: AttackConfig = AttackConfig()) throws -> Recovery {
    let wb = try Whitebox(key: key, encrypt: encrypt, seed: seed == 0 ? 1 : seed, identity: identity, forceCPU: cpu)
    if !cpu, let name = wb.engine?.deviceName {
        print("GPU  \(name)")
    } else {
        print("CPU  fallback")
    }
    if !cpu { try checkOracle(wb) }
    var rng = SplitMix64(state: seed == 0 ? 1 : seed)
    let mref = rng.bytes(16)
    var cfg = config
    cfg.useReverse = reverse
    cfg.doubleRS = doubleRS
    cfg.wantEncodings = encodings
    let rec = try recover(wb: wb, mref: mref, config: cfg, rng: &rng)
    guard rec.key == key else {
        throw AttackError.fail("recovered \(hex(rec.key)) != \(hex(key))")
    }
    if encodings, let inn = rec.inputEncoding, let out = rec.outputEncoding {
        try matchGeneratedEncodings(wb, inn, out)
    }
    return rec
}

func tableAt(_ flat: [UInt8], _ round: Int, _ byte: Int) -> [UInt8] {
    let off = (round * 16 + byte) * 256
    return Array(flat[off..<off + 256])
}

func matchGeneratedEncodings(_ wb: Whitebox, _ input: Encoding16, _ output: Encoding16) throws {
    // Decrypt white-box input is encoding[nr]; its output is encoding[0].
    let inRound = wb.isEncrypt ? 0 : wb.nr
    let outRound = wb.isEncrypt ? wb.nr : 0
    for b in 0..<16 {
        let inEnc = tableAt(wb.encTab, inRound, b)
        let inDec = tableAt(wb.decTab, inRound, b)
        let outEnc = tableAt(wb.encTab, outRound, b)
        let outDec = tableAt(wb.decTab, outRound, b)
        if input.enc[b] != inEnc {
            throw AttackError.fail("input encoding byte \(b) is not the white-box encode table (decode match=\(input.enc[b] == inDec))")
        }
        if output.enc[b] != outEnc {
            throw AttackError.fail("output encoding byte \(b) is not the white-box encode table (decode match=\(output.enc[b] == outDec))")
        }
    }
}

func selftest() throws {
    let t0 = mono()
    try selfTestLinearAlgebra()
    try nist()
    print("algebra and NIST AES ok")
    let cases: [(String, [UInt8], Bool, Bool, Bool, Bool)] = [
        ("AES-128 enc reverse identity", Array(0..<16).map { UInt8($0) }, true, true, true, false),
        ("AES-128 enc reverse random", Array(0..<16).map { UInt8($0) }, true, true, false, false),
        ("AES-128 enc search random", Array(repeating: 0x42, count: 16), true, false, false, false),
        ("AES-128 dec reverse random", Array(0..<16).map { UInt8($0) }, false, true, false, false),
        ("AES-256 enc reverse random", Array(0..<32).map { UInt8($0) }, true, true, false, false),
    ]
    for (name, key, enc, rev, ident, _) in cases {
        let rec = try runOne(key: key, seed: 7, encrypt: enc, reverse: rev, doubleRS: false, identity: ident, cpu: false, encodings: true)
        print(String(format: "ok  %-28@ %6.1f ms  key %@", name as NSString, rec.milliseconds, hex(rec.key) as NSString))
    }
    let cpuKey = Array(0..<16).map { UInt8($0) }
    let cpuRec = try runOne(key: cpuKey, seed: 3, encrypt: true, reverse: true, doubleRS: false, identity: true, cpu: true, encodings: true)
    print(String(format: "ok  CPU reverse identity       %6.1f ms", cpuRec.milliseconds))
    print(String(format: "selftest passed in %.1f ms", elapsedMS(t0, mono())))
}

func bench(_ n: Int) throws {
    let key = [UInt8](repeating: 0x2b, count: 16)
    let gpu = try Whitebox(key: key, encrypt: true, seed: 1, identity: false, forceCPU: false)
    let cpu = try Whitebox(key: key, encrypt: true, seed: 1, identity: false, forceCPU: true)
    // Same encodings are not shared; throughput only. Use identity so the work is comparable.
    let g = try Whitebox(key: key, encrypt: true, seed: 1, identity: true, forceCPU: false)
    let c = try Whitebox(key: key, encrypt: true, seed: 1, identity: true, forceCPU: true)
    _ = gpu
    _ = cpu
    func time(_ wb: Whitebox, _ n: Int) throws -> Double {
        let chunk = 1 << 16
        var left = n
        var pt = [UInt8](repeating: 0, count: 16)
        let t0 = mono()
        while left > 0 {
            let m = min(chunk, left)
            var jobs = [Job]()
            jobs.reserveCapacity(m)
            for i in 0..<m {
                pt[0] = UInt8(i & 0xff)
                pt[1] = UInt8((i >> 8) & 0xff)
                jobs.append(Job.pack(pt, faultRound: 8, byte: UInt8(i & 15), xor: UInt8((i % 255) + 1)))
            }
            _ = try wb.evalJobs(jobs)
            left -= m
        }
        return elapsedMS(t0, mono()) / 1000
    }
    let ng = min(n, 1 << 20)
    let gs = try time(g, ng)
    print(String(format: "GPU  %d faulted AES-128   %.3f s   %.2f M/s   %@", ng, gs, Double(ng) / gs / 1e6, (g.engine?.deviceName ?? "") as NSString))
    let nc = min(n, 1 << 16)
    let cs = try time(c, nc)
    print(String(format: "CPU  %d faulted AES-128   %.3f s   %.2f M/s", nc, cs, Double(nc) / cs / 1e6))
}

setvbuf(stdout, nil, _IONBF, 0)
let opt = parse()
Log.verbose = opt.verbose
do {
    if opt.selftest {
        try selftest()
    } else if let n = opt.bench {
        try bench(n)
    } else if let command = opt.oracle {
        Log.quiet = opt.noProgress
        let rec = try runExternal(command: command, expected: opt.key, config: attackConfig(opt))
        print("recovered \(hex(rec.key))")
        print(String(format: "total %.1f ms", rec.milliseconds))
    } else {
        let keyLen = opt.bits / 8
        guard [16, 24, 32].contains(keyLen) else { throw AttackError.fail("--bits must be 128, 192, or 256") }
        var seed = opt.seed
        if seed == 0 { seed = UInt64.random(in: 1...UInt64.max) }
        let key = opt.key ?? {
            var rng = SplitMix64(state: seed)
            return rng.bytes(keyLen)
        }()
        guard key.count == keyLen else { throw AttackError.fail("key length does not match --bits") }
        print("seed \(seed)")
        print("key  \(hex(key))")
        Log.quiet = opt.noProgress
        let rec = try runOne(key: key, seed: seed, encrypt: opt.encrypt, reverse: opt.useReverse, doubleRS: opt.doubleRS, identity: opt.identity, cpu: opt.cpu, encodings: opt.encodings, config: attackConfig(opt))
        print("recovered \(hex(rec.key))")
        print(String(format: "total %.1f ms", rec.milliseconds))
        if opt.verbose, let inn = rec.inputEncoding, let out = rec.outputEncoding {
            print("input encoding byte0 \(hex(Array(inn.enc[0].prefix(16))))...")
            print("output encoding byte0 \(hex(Array(out.enc[0].prefix(16))))...")
        }
    }
} catch {
    fputs("error: \(error)\n", stderr)
    exit(1)
}
