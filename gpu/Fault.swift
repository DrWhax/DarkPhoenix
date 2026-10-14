import Foundation

struct FaultPositionError: Error, CustomStringConvertible {
    var roundNumber: Int
    var bytes: [Int]?
    var description: String {
        if let bytes, !bytes.isEmpty {
            return "Wrong position for fault at round \(roundNumber) byte \(bytes)"
        }
        return "Wrong position for fault at round \(roundNumber)"
    }
}

struct Quad: Hashable {
    var a, b, c, d: UInt8
    init(_ xs: [UInt8]) {
        a = xs.count > 0 ? xs[0] : 0
        b = xs.count > 1 ? xs[1] : 0
        c = xs.count > 2 ? xs[2] : 0
        d = xs.count > 3 ? xs[3] : 0
    }
}

struct FaultPositionValidator {
    let fround: Int
    let encrypt: Bool
    let outputF: [Encoding16]
    let reverseMC: Bool
    let hasSecond: Bool
    var committed = [Bool](repeating: false, count: 16)
    var columnByByte = [Int?](repeating: nil, count: 16)
    var columnPos = [[Int]](repeating: [], count: 4)
    var committedFault = [Set<Quad>](repeating: [], count: 4)
    var foundColumn = 0
    let commonInput: [UInt8]
    let commonOutput: [UInt8]
    let commonOutput2: [UInt8]?

    static func make(wb: AttackTarget, fround: Int, outputF: [Encoding16], reverseMC: Bool) throws -> FaultPositionValidator {
        let input = (0..<16).map { _ in UInt8.random(in: 0...255) }
        let raw = try wb.applyRaw(input)
        let out = view(raw, encrypt: wb.isEncrypt, outputF: outputF, reverseMC: reverseMC, second: false)
        let second: [UInt8]? = hasSecondView(outputF: outputF, reverseMC: reverseMC)
            ? view(raw, encrypt: wb.isEncrypt, outputF: outputF, reverseMC: reverseMC, second: true)
            : nil
        return FaultPositionValidator(
            fround: fround, encrypt: wb.isEncrypt, outputF: outputF, reverseMC: reverseMC,
            hasSecond: second != nil, commonInput: input, commonOutput: out, commonOutput2: second)
    }

    /// Returns whether the position was accepted. Mutates on success.
    mutating func accept(wb: AttackTarget, fpos: Int) throws -> Bool {
        if committed[fpos] { throw AttackError.fail("position \(fpos) already committed") }
        guard let first = try probe(wb, fpos, 1) else { return false }
        let faultPosition = first.positions
        let col0 = columnByByte[faultPosition[0]]
        if !faultPosition.allSatisfy({ columnByByte[$0] == col0 }) { return false }
        if let col0 {
            if columnPos[col0].count == 4 { return false }
            if committedFault[col0].contains(first.quad) { return false }
        } else if foundColumn == 4 {
            return false
        }
        var seen: Set<Quad> = [first.quad]
        for fvalue in 2...255 {
            guard let next = try probe(wb, fpos, fvalue) else { return false }
            if next.positions != faultPosition { return false }
            if seen.contains(next.quad) { return false }
            if let col0, committedFault[col0].contains(next.quad) { return false }
            seen.insert(next.quad)
        }
        committed[fpos] = true
        var col = col0
        if col == nil {
            col = foundColumn
            foundColumn += 1
            for p in faultPosition { columnByByte[p] = col }
        }
        columnPos[col!].append(fpos)
        committedFault[col!].formUnion(seen)
        return true
    }

    var allFound: Bool { committed.allSatisfy { $0 } }

    private func probe(_ wb: AttackTarget, _ fpos: Int, _ xor: Int) throws -> (positions: [Int], quad: Quad)? {
        let raw = try wb.applyFaultRaw(commonInput, round: fround, byte: fpos, xor: UInt8(xor))
        let output = view(raw, encrypt: encrypt, outputF: outputF, reverseMC: reverseMC, second: false)
        let positions = (0..<16).filter { commonOutput[$0] != output[$0] }
        var ok = positions.count == 4
        if ok, let base2 = commonOutput2 {
            let output2 = view(raw, encrypt: encrypt, outputF: outputF, reverseMC: reverseMC, second: true)
            ok = (0..<16).allSatisfy { base2[$0] != output2[$0] }
        }
        if !ok { return nil }
        return (positions, Quad(positions.map { output[$0] }))
    }
}

func hasSecondView(outputF: [Encoding16], reverseMC: Bool) -> Bool {
    if outputF.isEmpty { return false }
    if reverseMC { return true }
    return outputF.count > 1
}

func view(_ raw: [UInt8], encrypt: Bool, outputF: [Encoding16], reverseMC: Bool, second: Bool) -> [UInt8] {
    if !second {
        return attackView(raw, encryptWB: encrypt, outputF: outputF, reverseMC: reverseMC)
    }
    if reverseMC {
        return attackView(raw, encryptWB: encrypt, outputF: outputF, reverseMC: false)
    }
    return attackView(raw, encryptWB: encrypt, outputF: Array(outputF.dropLast()), reverseMC: reverseMC)
}

struct AutoFaultState {
    var available: [Int: [Bool]] = [:]
    var lastRound: Int?
    let validateRepeats = 1

    mutating func select(wb: AttackTarget, fround: Int, outputF: [Encoding16], reverseMC: Bool) throws {
        guard (0..<wb.nr).contains(fround) else {
            throw AttackError.fail("unsupported fault round \(fround)")
        }
        lastRound = fround
        if available[fround] == nil {
            available[fround] = [Bool](repeating: false, count: 16)
        }
        if available[fround]!.allSatisfy({ $0 }) { return }

        var validation = 0
        var firstLoop = true
        var tested = 0
        while firstLoop || validation < validateRepeats {
            firstLoop = false
            var helper = try FaultPositionValidator.make(wb: wb, fround: fround, outputF: outputF, reverseMC: reverseMC)
            var committedPos = 0
            for fbytes in 0..<16 where available[fround]![fbytes] {
                if try helper.accept(wb: wb, fpos: fbytes) {
                    committedPos += 1
                } else {
                    try wb.removeFaultPosition(fround, fbytes)
                    available[fround]![fbytes] = false
                }
            }
            if committedPos == 16 {
                if !helper.allFound { throw AttackError.fail("missing fault position") }
                validation += 1
                continue
            }
            validation = 0
            for fbytes in 0..<16 where !available[fround]![fbytes] {
                while true {
                    try wb.changeFaultPosition(fround, fbytes)
                    tested += 1
                    if !Log.quiet && tested % 16 == 0 {
                        print("  fault positions round \(fround): tested \(tested)")
                    }
                    if try helper.accept(wb: wb, fpos: fbytes) { break }
                    try wb.removeFaultPosition(fround, fbytes)
                }
                available[fround]![fbytes] = true
            }
            if !helper.allFound { throw AttackError.fail("missing fault position") }
        }
    }

    mutating func clear(wb: AttackTarget, fround: Int?, fbytes: Int?) throws {
        if fround == nil {
            for (round, flags) in available {
                for (byte, on) in flags.enumerated() where on {
                    try wb.removeFaultPosition(round, byte)
                }
            }
            available = [:]
            return
        }
        let round = fround!
        guard var flags = available[round] else { return }
        if fbytes == nil {
            for (byte, on) in flags.enumerated() where on {
                try wb.removeFaultPosition(round, byte)
            }
            available[round] = nil
            return
        }
        let byte = fbytes!
        if flags[byte] {
            try wb.removeFaultPosition(round, byte)
            flags[byte] = false
            available[round] = flags
        }
    }
}
