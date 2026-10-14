import Foundation
import Metal

private enum ShaderCache {
    static var source: String?
    static var library: MTLLibrary?
}

final class MetalEngine {
    let device: MTLDevice
    let queue: MTLCommandQueue
    let deviceName: String
    private let pipeEval: MTLComputePipelineState
    private let pipeStep1: MTLComputePipelineState
    private let pipeStep2: MTLComputePipelineState
    private let rkBuf: MTLBuffer
    private let encBuf: MTLBuffer
    private let decBuf: MTLBuffer
    private let permBuf: MTLBuffer
    private let revBuf: MTLBuffer
    private let sboxBuf: MTLBuffer
    private let invBuf: MTLBuffer
    private let mulBuf: MTLBuffer
    private var jobBuf: MTLBuffer?
    private var outBuf: MTLBuffer?
    private var step1Flags: MTLBuffer?
    private var step1Inputs: MTLBuffer?
    private var step2Plain: MTLBuffer?
    private var step2Fault: MTLBuffer?
    private var step2Out: MTLBuffer?
    private let nr: Int

    init(nr: Int, roundKeys: [UInt8], encTab: [UInt8], decTab: [UInt8], roundPerm: [UInt8], revPerm: [UInt8]) throws {
        guard let device = MTLCreateSystemDefaultDevice(), let queue = device.makeCommandQueue() else {
            throw AttackError.fail("Metal device unavailable")
        }
        self.device = device
        self.queue = queue
        self.deviceName = device.name
        self.nr = nr
        let src = try Self.loadShader()
        let lib: MTLLibrary
        if let cached = ShaderCache.library, ShaderCache.source == src {
            lib = cached
        } else {
            let opts = MTLCompileOptions()
            opts.languageVersion = .version3_0
            do {
                lib = try device.makeLibrary(source: src, options: opts)
            } catch {
                throw AttackError.fail("Metal compile failed: \(error)")
            }
            ShaderCache.source = src
            ShaderCache.library = lib
        }
        pipeEval = try device.makeComputePipelineState(function: lib.makeFunction(name: "wb_eval")!)
        pipeStep1 = try device.makeComputePipelineState(function: lib.makeFunction(name: "step1_search")!)
        pipeStep2 = try device.makeComputePipelineState(function: lib.makeFunction(name: "step2_eval")!)
        rkBuf = try Self.buf(device, roundKeys)
        encBuf = try Self.buf(device, encTab)
        decBuf = try Self.buf(device, decTab)
        permBuf = try Self.buf(device, roundPerm)
        revBuf = try Self.buf(device, revPerm)
        sboxBuf = try Self.buf(device, AESConst.sbox)
        invBuf = try Self.buf(device, AESConst.invSbox)
        mulBuf = try Self.buf(device, AESConst.mulTablesFlat())
        guard MemoryLayout<Job>.stride == 20 else {
            throw AttackError.fail("Job stride \(MemoryLayout<Job>.stride) != 20")
        }
    }

    func eval(_ jobs: UnsafePointer<Job>, _ n: Int, _ out: UnsafeMutablePointer<UInt8>, encrypt: Bool) throws {
        if n == 0 { return }
        let jb = try ensure(&jobBuf, n * 20)
        let ob = try ensure(&outBuf, n * 16)
        jb.contents().copyMemory(from: UnsafeRawPointer(jobs), byteCount: n * 20)
        var p = (UInt32(nr), UInt32(encrypt ? 1 : 0), UInt32(n))
        try dispatch(pipeEval, n) { enc in
            enc.setBytes(&p, length: 12, index: 0)
            self.bindTables(enc)
            enc.setBuffer(jb, offset: 0, index: 9)
            enc.setBuffer(ob, offset: 0, index: 10)
        }
        out.update(from: ob.contents().bindMemory(to: UInt8.self, capacity: n * 16), count: n * 16)
    }

    func step2(_ plains: UnsafePointer<UInt8>, _ faultBytes: UnsafePointer<UInt8>, faultRound: Int, encrypt: Bool, out: UnsafeMutablePointer<UInt8>) throws {
        let n = 16 * 256 * 256
        let pb = try ensure(&step2Plain, 16 * 256 * 16)
        let fb = try ensure(&step2Fault, 16)
        let ob = try ensure(&step2Out, n * 16)
        pb.contents().copyMemory(from: UnsafeRawPointer(plains), byteCount: 16 * 256 * 16)
        fb.contents().copyMemory(from: UnsafeRawPointer(faultBytes), byteCount: 16)
        var p = (UInt32(nr), UInt32(encrypt ? 1 : 0), UInt32(faultRound))
        try dispatch(pipeStep2, n) { enc in
            enc.setBytes(&p, length: 12, index: 0)
            self.bindTables(enc)
            enc.setBuffer(pb, offset: 0, index: 9)
            enc.setBuffer(fb, offset: 0, index: 10)
            enc.setBuffer(ob, offset: 0, index: 11)
        }
        out.update(from: ob.contents().bindMemory(to: UInt8.self, capacity: n * 16), count: n * 16)
    }

    func step1Reset(flags: [UInt32], inputs: [UInt8]) throws {
        let fb = try ensure(&step1Flags, Step1Layout.slotCount * 4)
        let ib = try ensure(&step1Inputs, Step1Layout.slotCount * 16)
        flags.withUnsafeBytes { fb.contents().copyMemory(from: $0.baseAddress!, byteCount: flags.count * 4) }
        inputs.withUnsafeBytes { ib.contents().copyMemory(from: $0.baseAddress!, byteCount: inputs.count) }
    }

    func step1Run(base: UInt64, count: Int, valueRef: [UInt8], doubleRS: Bool, encrypt: Bool) throws -> [UInt32] {
        guard let fb = step1Flags, let ib = step1Inputs else {
            throw AttackError.fail("step1Reset was not called")
        }
        var p = (UInt32(nr), UInt32(encrypt ? 1 : 0), UInt32(doubleRS ? 1 : 0), UInt32(count), UInt32(truncatingIfNeeded: base), UInt32(truncatingIfNeeded: base >> 32))
        let vref = valueRef
        try dispatch(pipeStep1, count) { enc in
            enc.setBytes(&p, length: MemoryLayout.size(ofValue: p), index: 0)
            self.bindTables(enc)
            vref.withUnsafeBytes { raw in
                enc.setBytes(raw.baseAddress!, length: 16, index: 9)
            }
            enc.setBuffer(fb, offset: 0, index: 10)
            enc.setBuffer(ib, offset: 0, index: 11)
        }
        let ptr = fb.contents().bindMemory(to: UInt32.self, capacity: Step1Layout.slotCount)
        return Array(UnsafeBufferPointer(start: ptr, count: Step1Layout.slotCount))
    }

    func copyStep1Inputs() throws -> [UInt8] {
        guard let ib = step1Inputs else { throw AttackError.fail("step1 inputs missing") }
        return Array(UnsafeBufferPointer(start: ib.contents().bindMemory(to: UInt8.self, capacity: Step1Layout.slotCount * 16), count: Step1Layout.slotCount * 16))
    }

    private func bindTables(_ enc: MTLComputeCommandEncoder) {
        enc.setBuffer(rkBuf, offset: 0, index: 1)
        enc.setBuffer(encBuf, offset: 0, index: 2)
        enc.setBuffer(decBuf, offset: 0, index: 3)
        enc.setBuffer(permBuf, offset: 0, index: 4)
        enc.setBuffer(revBuf, offset: 0, index: 5)
        enc.setBuffer(sboxBuf, offset: 0, index: 6)
        enc.setBuffer(invBuf, offset: 0, index: 7)
        enc.setBuffer(mulBuf, offset: 0, index: 8)
    }

    private func dispatch(_ pipe: MTLComputePipelineState, _ n: Int, _ bind: (MTLComputeCommandEncoder) -> Void) throws {
        guard let cmd = queue.makeCommandBuffer(), let enc = cmd.makeComputeCommandEncoder() else {
            throw AttackError.fail("failed to create Metal command buffer")
        }
        enc.setComputePipelineState(pipe)
        bind(enc)
        let width = min(256, max(n, 1))
        enc.dispatchThreads(MTLSize(width: n, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: width, height: 1, depth: 1))
        enc.endEncoding()
        cmd.commit()
        cmd.waitUntilCompleted()
        if cmd.status != .completed {
            let err = cmd.error?.localizedDescription ?? "unknown"
            throw AttackError.fail("Metal dispatch failed: \(err)")
        }
    }

    private func ensure(_ slot: inout MTLBuffer?, _ bytes: Int) throws -> MTLBuffer {
        if let b = slot, b.length >= bytes { return b }
        guard let b = device.makeBuffer(length: max(bytes, 16), options: .storageModeShared) else {
            throw AttackError.fail("Metal buffer alloc failed (\(bytes) bytes)")
        }
        slot = b
        return b
    }

    private static func buf(_ device: MTLDevice, _ bytes: [UInt8]) throws -> MTLBuffer {
        guard let b = device.makeBuffer(bytes: bytes, length: max(bytes.count, 16), options: .storageModeShared) else {
            throw AttackError.fail("Metal buffer alloc failed")
        }
        return b
    }

    private static func loadShader() throws -> String {
        var paths: [String] = []
        if let env = ProcessInfo.processInfo.environment["DARKPHOENIX_SHADER"] { paths.append(env) }
        let exe = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent("Shaders.metal").path
        paths.append(exe)
        paths.append("Shaders.metal")
        paths.append("gpu/Shaders.metal")
        for p in paths {
            if let s = try? String(contentsOfFile: p, encoding: .utf8) { return s }
        }
        throw AttackError.fail("Shaders.metal not found (looked in \(paths.joined(separator: ", ")))")
    }
}
