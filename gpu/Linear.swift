// GF(2) linear algebra used in place of the Sage step-3 resolver.
import Foundation

struct Mat8 {
    var r: [UInt8]

    static var zero: Mat8 { Mat8(r: [UInt8](repeating: 0, count: 8)) }
    static var I: Mat8 {
        var m = Mat8.zero
        for i in 0..<8 { m.r[i] = UInt8(1 << i) }
        return m
    }

    func mul(_ b: Mat8) -> Mat8 {
        var c = Mat8.zero
        for i in 0..<8 {
            var row: UInt8 = 0
            var bits = r[i]
            var k = 0
            while bits != 0 {
                if bits & 1 != 0 { row ^= b.r[k] }
                bits >>= 1
                k += 1
            }
            c.r[i] = row
        }
        return c
    }

    func transposed() -> Mat8 {
        var t = Mat8.zero
        for i in 0..<8 {
            for j in 0..<8 where (r[i] >> j) & 1 == 1 {
                t.r[j] |= UInt8(1 << i)
            }
        }
        return t
    }

    func inv() -> Mat8? {
        var m = r
        var n = Mat8.I.r
        for col in 0..<8 {
            var pivot = -1
            for row in col..<8 where (m[row] >> col) & 1 == 1 {
                pivot = row
                break
            }
            if pivot < 0 { return nil }
            if pivot != col {
                m.swapAt(pivot, col)
                n.swapAt(pivot, col)
            }
            for row in 0..<8 where row != col && (m[row] >> col) & 1 == 1 {
                m[row] ^= m[col]
                n[row] ^= n[col]
            }
        }
        return Mat8(r: n)
    }
}

func mulMat(_ k: UInt8) -> Mat8 {
    var m = Mat8.zero
    for i in 0..<8 { m.r[i] = gmul(k, UInt8(1 << i)) }
    return m
}

func applyMat(_ x: UInt8, _ g: Mat8) -> UInt8 {
    var o: UInt8 = 0
    var v = x
    for k in 0..<8 {
        if v & 1 == 1 { o ^= g.r[k] }
        v >>= 1
    }
    return o
}

func tableFromMat(_ g: Mat8) -> [UInt8] {
    (0..<256).map { applyMat(UInt8($0), g) }
}

func matFromMap(_ table: [UInt8]) -> Mat8 {
    var m = Mat8.zero
    for i in 0..<8 { m.r[i] = table[1 << i] }
    return m
}

func gf2Nullspace(_ eqsIn: [UInt64]) -> [UInt64] {
    var a = eqsIn
    if a.count < 64 { a.append(contentsOf: repeatElement(0, count: 64 - a.count)) }
    if a.count > 64 { a = Array(a.prefix(64)) }
    var pivotOfCol = [Int](repeating: -1, count: 64)
    var row = 0
    for col in 0..<64 {
        var sel = -1
        var i = row
        while i < 64 {
            if (a[i] >> UInt64(col)) & 1 == 1 { sel = i; break }
            i += 1
        }
        if sel < 0 { continue }
        a.swapAt(sel, row)
        pivotOfCol[col] = row
        for r in 0..<64 where r != row && (a[r] >> UInt64(col)) & 1 == 1 {
            a[r] ^= a[row]
        }
        row += 1
        if row == 64 { break }
    }
    var basis: [UInt64] = []
    for free in 0..<64 where pivotOfCol[free] < 0 {
        var v = UInt64(1) << UInt64(free)
        for c in 0..<64 {
            let pr = pivotOfCol[c]
            if pr >= 0 && (a[pr] >> UInt64(free)) & 1 == 1 {
                v |= UInt64(1) << UInt64(c)
            }
        }
        basis.append(v)
    }
    return basis
}

func intertwinerSystem(L: Mat8, M: Mat8, swapped: Bool) -> [UInt64] {
    var eqs = [UInt64](repeating: 0, count: 64)
    for i in 0..<8 {
        for j in 0..<8 {
            var coef: UInt64 = 0
            if !swapped {
                for k in 0..<8 {
                    if (L.r[k] >> j) & 1 == 1 { coef ^= UInt64(1) << UInt64(i * 8 + k) }
                    if (M.r[i] >> k) & 1 == 1 { coef ^= UInt64(1) << UInt64(k * 8 + j) }
                }
            } else {
                for k in 0..<8 {
                    if (L.r[i] >> k) & 1 == 1 { coef ^= UInt64(1) << UInt64(k * 8 + j) }
                    if (M.r[k] >> j) & 1 == 1 { coef ^= UInt64(1) << UInt64(i * 8 + k) }
                }
            }
            eqs[i * 8 + j] = coef
        }
    }
    return eqs
}

func matFromBits(_ bits: UInt64) -> Mat8 {
    var m = Mat8.zero
    for i in 0..<8 {
        var row: UInt8 = 0
        for j in 0..<8 where (bits >> UInt64(i * 8 + j)) & 1 == 1 {
            row |= UInt8(1 << j)
        }
        m.r[i] = row
    }
    return m
}

struct Oriented {
    var L: Mat8
    var M: Mat8
    var swapped: Bool
}

func orient(L: Mat8, M: Mat8, direction: Int) -> Oriented {
    let tl = (direction & 2) != 0
    let tm = (direction & 4) != 0
    return Oriented(L: tl ? L.transposed() : L, M: tm ? M.transposed() : M, swapped: (direction & 1) != 0)
}

func intertwinerBasis(L: Mat8, M: Mat8, direction: Int) -> [UInt64] {
    let o = orient(L: L, M: M, direction: direction)
    return gf2Nullspace(intertwinerSystem(L: o.L, M: o.M, swapped: o.swapped))
}

func invertibleFromBasis(_ basis: [UInt64], limit: Int) -> [Mat8] {
    let dim = basis.count
    if dim == 0 || dim > 16 { return [] }
    let n = 1 << min(dim, 12)
    var out: [Mat8] = []
    out.reserveCapacity(min(limit, 32))
    for mask in 1..<n {
        var bits: UInt64 = 0
        for i in 0..<dim where (mask >> i) & 1 == 1 { bits ^= basis[i] }
        let g = matFromBits(bits)
        if g.inv() != nil {
            out.append(g)
            if out.count >= limit { break }
        }
    }
    return out
}

func candidateMatrices(encrypt: Bool) -> [(String, Mat8)] {
    func inv(_ m: Mat8) -> Mat8 {
        guard let i = m.inv() else { fatalError("singular MixColumns matrix") }
        return i
    }
    if encrypt {
        let m2 = mulMat(2), m3 = mulMat(3)
        let i2 = inv(m2), i3 = inv(m3)
        return [
            ("2", m2),
            ("2*3", m2.mul(m3)),
            ("2*3^(-1)", m2.mul(i3)),
            ("2*3^(-2)", m2.mul(i3).mul(i3)),
            ("2^(-1)", i2),
            ("2^(-1)*3", i2.mul(m3)),
            ("2^(-1)*3^(-1)", i2.mul(i3)),
            ("2^(-1)*3^(2)", i2.mul(m3).mul(m3)),
            ("2^(-2)*3", i2.mul(i2).mul(m3)),
            ("2^(2)*3^(-1)", m2.mul(m2).mul(i3)),
            ("3", m3),
            ("3^(-1)", i3),
        ]
    }
    let m9 = mulMat(9), m11 = mulMat(11), m13 = mulMat(13), m14 = mulMat(14)
    let i9 = inv(m9), i11 = inv(m11), i13 = inv(m13), i14 = inv(m14)
    return [
        ("9*11*13^(-2)", m9.mul(m11).mul(i13).mul(i13)),
        ("9*11*14^(-2)", m9.mul(m11).mul(i14).mul(i14)),
        ("9*11^(-1)*13*14^(-1)", m9.mul(i11).mul(m13).mul(i14)),
        ("9*11^(-1)*13^(-1)*14", m9.mul(i11).mul(i13).mul(m14)),
        ("9^(-1)*11*13*14^(-1)", i9.mul(m11).mul(m13).mul(i14)),
        ("9^(-1)*11*13^(-1)*14", i9.mul(m11).mul(i13).mul(m14)),
        ("9^(-1)*11^(-1)*13^(2)", i9.mul(i11).mul(m13).mul(m13)),
        ("9^(-1)*11^(-1)*14^(2)", i9.mul(i11).mul(m14).mul(m14)),
        ("9^(-2)*13*14", i9.mul(i9).mul(m13).mul(m14)),
        ("9^(2)*13^(-1)*14^(-1)", m9.mul(m9).mul(i13).mul(i14)),
        ("11^(-2)*13*14", i11.mul(i11).mul(m13).mul(m14)),
        ("11^(2)*13^(-1)*14^(-1)", m11.mul(m11).mul(i13).mul(i14)),
    ]
}

func associateFault(name: String, p0: Int, p1: Int) -> (Int, Int)? {
    let table: [String: [Int: (Int, Int)]] = [
        "2": keyMap([(1, 0, 0, 3), (2, 3, 1, 2), (3, 2, 2, 1), (0, 1, 3, 0)]),
        "2*3": keyMap([(1, 0, 0, 2), (2, 3, 0, 2), (0, 1, 2, 0), (3, 2, 2, 0)]),
        "2*3^(-1)": keyMap([(0, 1, 1, 3), (3, 2, 1, 3), (1, 0, 3, 1), (2, 3, 3, 1)]),
        "2*3^(-2)": keyMap([(3, 2, 0, 3), (0, 1, 1, 2), (1, 0, 2, 1), (2, 3, 3, 0)]),
        "2^(-1)": keyMap([(0, 1, 0, 3), (3, 2, 1, 2), (2, 3, 2, 1), (1, 0, 3, 0)]),
        "2^(-1)*3": keyMap([(1, 0, 1, 3), (2, 3, 1, 3), (0, 1, 3, 1), (3, 2, 3, 1)]),
        "2^(-1)*3^(-1)": keyMap([(0, 1, 0, 2), (3, 2, 0, 2), (1, 0, 2, 0), (2, 3, 2, 0)]),
        "2^(-1)*3^(2)": keyMap([(2, 3, 0, 3), (1, 0, 1, 2), (0, 1, 2, 1), (3, 2, 3, 0)]),
        "2^(-2)*3": keyMap([(0, 1, 0, 1), (1, 0, 1, 0), (2, 3, 2, 3), (3, 2, 3, 2)]),
        "2^(2)*3^(-1)": keyMap([(1, 0, 0, 1), (0, 1, 1, 0), (3, 2, 2, 3), (2, 3, 3, 2)]),
        "3": keyMap([(2, 3, 0, 1), (3, 2, 1, 0), (0, 1, 2, 3), (1, 0, 3, 2)]),
        "3^(-1)": keyMap([(3, 2, 0, 1), (2, 3, 1, 0), (1, 0, 2, 3), (0, 1, 3, 2)]),
        "9*11*14^(-2)": keyMap([(0, 1, 0, 1), (1, 0, 1, 0), (2, 3, 2, 3), (3, 2, 3, 2)]),
        "9^(-1)*11^(-1)*14^(2)": keyMap([(1, 0, 0, 1), (0, 1, 1, 0), (3, 2, 2, 3), (2, 3, 3, 2)]),
        "9*11*13^(-2)": keyMap([(2, 3, 0, 1), (3, 2, 1, 0), (0, 1, 2, 3), (1, 0, 3, 2)]),
        "9^(-1)*11^(-1)*13^(2)": keyMap([(3, 2, 0, 1), (2, 3, 1, 0), (1, 0, 2, 3), (0, 1, 3, 2)]),
        "9*11^(-1)*13*14^(-1)": keyMap([(0, 1, 0, 2), (3, 2, 0, 2), (1, 0, 2, 0), (2, 3, 2, 0)]),
        "9^(-1)*11*13^(-1)*14": keyMap([(1, 0, 0, 2), (2, 3, 0, 2), (0, 1, 2, 0), (3, 2, 2, 0)]),
        "9^(2)*13^(-1)*14^(-1)": keyMap([(0, 1, 0, 3), (3, 2, 1, 2), (2, 3, 2, 1), (1, 0, 3, 0)]),
        "9^(-2)*13*14": keyMap([(1, 0, 0, 3), (2, 3, 1, 2), (3, 2, 2, 1), (0, 1, 3, 0)]),
        "11^(2)*13^(-1)*14^(-1)": keyMap([(2, 3, 0, 3), (1, 0, 1, 2), (0, 1, 2, 1), (3, 2, 3, 0)]),
        "11^(-2)*13*14": keyMap([(3, 2, 0, 3), (0, 1, 1, 2), (1, 0, 2, 1), (2, 3, 3, 0)]),
        "9*11^(-1)*13^(-1)*14": keyMap([(0, 1, 1, 3), (3, 2, 1, 3), (1, 0, 3, 1), (2, 3, 3, 1)]),
        "9^(-1)*11*13*14^(-1)": keyMap([(1, 0, 1, 3), (2, 3, 1, 3), (0, 1, 3, 1), (3, 2, 3, 1)]),
    ]
    return table[name]?[p0 * 4 + p1]
}

private func keyMap(_ rows: [(Int, Int, Int, Int)]) -> [Int: (Int, Int)] {
    var d: [Int: (Int, Int)] = [:]
    for r in rows { d[r.0 * 4 + r.1] = (r.2, r.3) }
    return d
}

func selfTestLinearAlgebra() throws {
    let m2 = mulMat(2)
    guard m2.inv() != nil else { throw AttackError.fail("M_2 not invertible") }
    guard m2.mul(m2.inv()!) .r == Mat8.I.r else { throw AttackError.fail("M_2 inverse") }
    let comm = gf2Nullspace(intertwinerSystem(L: m2, M: m2, swapped: false))
    guard comm.count == 8 else {
        throw AttackError.fail("commutant of multiplication-by-2 has dim \(comm.count), expected 8")
    }
    let cands = candidateMatrices(encrypt: true)
    guard cands.count == 12 else { throw AttackError.fail("enc candidate count") }
    for i in cands.indices {
        for j in cands.indices {
            let dim = intertwinerBasis(L: cands[i].1, M: cands[j].1, direction: 0).count
            if i == j {
                guard dim == 8 else { throw AttackError.fail("\(cands[i].0) commutant dim \(dim)") }
            } else if dim != 0 {
                throw AttackError.fail("candidates \(cands[i].0) and \(cands[j].0) are similar (dim \(dim))")
            }
        }
    }
    // A random invertible gauge is recovered up to the commutant.
    var g = Mat8.zero
    g.r = [1, 2, 4, 8, 16, 32, 64, 128] // identity, boring but invertible
    // Use a non-scalar intertwiner built as multiplication by 3, which commutes with M_2? 
    // multiplication-by-3 commutes with multiplication-by-2. L = inv(G)*M*G with G = mul-by-3
    // should be similar via direction 0.
    let G = mulMat(3)
    let L = G.inv()!.mul(m2).mul(G) // inv(G)*M*G means G^{-1} * M * G, so L = Ginv.mul(m2).mul(G)
    // Wait: column convention (G^{-1}*M*G) vs our row storage. 
    // We only check that some direction has an invertible intertwiner with M_2.
    var matched = false
    for d in 0..<8 {
        if intertwinerBasis(L: L, M: m2, direction: d).count > 0 { matched = true; break }
    }
    guard matched else { throw AttackError.fail("failed to recognize a conjugated M_2") }
    _ = g
}
