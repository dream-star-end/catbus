import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { staticFile } from '../../../core/paths.js'
import { DEFAULT_SEED, isDeterministic, mulberry32, now as randNow } from '../../../core/rand.js'

/**
 * 小红书 Web 签名的纯 TS 实现。
 *
 * 移植自 `static/xhs/xhs_core/js/`（只读上游，不手改）：
 *   - `mns.js`：mns0301 / mns0101 / mns0201 三档（pack TLV → dsf 4-lane ARX → XOR 密钥流 / XXTEA → 自定义 base64/base58）
 *   - `xs_common.js`：X-S-Common 信封（变体 CRC32 + 自定义 base64）
 *   - `sign.js` 的 `signFull`：cookie 解析 → mns → xs 信封（x5/x6/x7）→ xt → xs_common
 *
 * 与 `js.ts` 经 node:vm 跑上游 JS 的路径逐字节对齐（golden 对拍为裁判）。
 * 确定性语义与 vm 路径一致：确定性模式下每次调用都从全新的
 * `mulberry32(DEFAULT_SEED)` 序列取值（vm 是每次新建 context，上游是每次新起 node 进程）；
 * 非确定性模式下走 `Math.random` / OS `randomBytes` / `Date.now`。
 *
 * 服务端下发的 DS 程序（Creator 0101 的 `_dsf`）是动态代码、无法静态移植，
 * 仍在隔离的 node:vm 里执行（见 `runDsfProgram`）。
 */

type ByteArray = number[]

// ---------------------------------------------------------------- 确定性随机源

/** 每次调用签名前进一次序列：确定性模式下返回全新的 mulberry32，否则返回 null（用宿主随机源）。 */
function freshDet(): (() => number) | null {
  return isDeterministic() ? mulberry32(DEFAULT_SEED) : null
}

function randFloat(det: (() => number) | null): number {
  return det ? det() : Math.random()
}

function randByte(det: (() => number) | null): number {
  return Math.floor(randFloat(det) * 256)
}

/** u32 LE：确定性模式下 4 次 Math.random 取字节（与 vm 里被代理的 crypto.randomBytes 一致），否则 OS 随机。 */
function randU32LE(det: (() => number) | null): number {
  if (!det) return randomBytes(4).readUInt32LE(0)
  const b0 = randByte(det)
  const b1 = randByte(det)
  const b2 = randByte(det)
  const b3 = randByte(det)
  return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0
}

// ---------------------------------------------------------------- 基础编码

const ALPHABET = 'MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G'
const MNS0101_ALPHABET = 'NOPQRStuvwxWXYZabcyz012DEFTKLMdefghijkl4563GHIJBC7mnop89+/'
const ALPHABET_XS = 'ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5'

function md5Bytes(s: string): ByteArray {
  return [...createHash('md5').update(String(s), 'utf8').digest()]
}

function le32(n: number): ByteArray {
  n >>>= 0
  return [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]
}

function le64(n: number): ByteArray {
  const out: ByteArray = []
  let b = BigInt(Math.trunc(n))
  for (let i = 0; i < 8; i++) {
    out.push(Number(b & 255n))
    b >>= 8n
  }
  return out
}

function strBytes(s: string): ByteArray {
  return [...Buffer.from(String(s), 'utf8')]
}

function hexToBytes(hex: string): ByteArray {
  const out: ByteArray = []
  for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16))
  return out
}

/** mns 0201/0301 的自定义 base64。 */
function base64Custom(bytes: ByteArray): string {
  let out = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!
    const b1 = bytes[i + 1]
    const b2 = bytes[i + 2]
    out += ALPHABET[b0 >> 2]
    out += ALPHABET[((b0 & 3) << 4) | ((b1 || 0) >> 4)]
    if (b1 === undefined) {
      out += '=='
      break
    }
    out += ALPHABET[((b1 & 15) << 2) | ((b2 || 0) >> 6)]
    if (b2 === undefined) {
      out += '='
      break
    }
    out += ALPHABET[b2 & 63]
  }
  return out
}

/** mns0101 的自定义 base58（前导零用字母表中的 `1` 表示）。 */
function base58Custom(bytes: ByteArray): string {
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  let body = ''
  while (value > 0n) {
    body = MNS0101_ALPHABET[Number(value % 58n)] + body
    value /= 58n
  }
  let zeros = 0
  for (const byte of bytes) {
    if (byte !== 0) break
    zeros++
  }
  return '1'.repeat(zeros) + body
}

/** xs / xs_common 信封的自定义 base64（与 mns 字母表不同）。 */
function b64XS(e: ByteArray): string {
  const a = e.length
  const c = a % 3
  const d: string[] = []
  let u = 0
  const l = a - c
  const s = 16383
  for (u = 0; u < l; u += s) {
    const end = u + s > l ? l : u + s
    for (let k = u; k < end; k += 3) {
      const t = (e[k]! << 16) + ((k + 1 < end ? e[k + 1]! : 0) << 8) + (k + 2 < end ? e[k + 2]! : 0)
      d.push(ALPHABET_XS[(t >> 18) & 63], ALPHABET_XS[(t >> 12) & 63], ALPHABET_XS[(t >> 6) & 63], ALPHABET_XS[t & 63])
    }
  }
  if (c === 1) {
    const t = e[a - 1]!
    d.push(ALPHABET_XS[t >> 2] + ALPHABET_XS[(t << 4) & 63] + '==')
  } else if (c === 2) {
    const t = (e[a - 2]! << 8) + e[a - 1]!
    d.push(ALPHABET_XS[t >> 10] + ALPHABET_XS[(t >> 4) & 63] + ALPHABET_XS[(t << 2) & 63] + '=')
  }
  return d.join('')
}

function encodeUtf8(e: string): ByteArray {
  const r = encodeURIComponent(e)
  const a: ByteArray = []
  for (let i = 0; i < r.length; i++) {
    const c = r.charAt(i)
    if (c === '%') {
      a.push(parseInt(r.charAt(i + 1) + r.charAt(i + 2), 16))
      i += 2
    } else a.push(c.charCodeAt(0))
  }
  return a
}

// ---------------------------------------------------------------- _dsf：自定义 4-lane ARX 哈希

function rotl(x: number, r: number): number {
  return (((x << r) | 0) + (x >>> (32 - r))) | 0
}

function dsf(data: ByteArray): ByteArray {
  const len = data.length
  const rd = (o: number): number => ((data[o] ?? 0) | ((data[o + 1] ?? 0) << 8) | ((data[o + 2] ?? 0) << 16) | ((data[o + 3] ?? 0) << 24)) | 0
  let h1 = (0x6d2b79f5 ^ len) | 0
  let h2 = (0x1b873593 ^ (len << 8)) | 0
  let h3 = (0x85ebca6b ^ (len << 16)) | 0
  let h4 = (0xc2b2ae35 ^ (len << 24)) | 0
  for (let i = 0; i + 8 <= len; i += 8) {
    const w0 = rd(i)
    const w1 = rd(i + 4)
    h1 = rotl((((h1 + w0) | 0) ^ h3) | 0, 7)
    h2 = rotl((((h2 ^ w0) | 0) + h4) | 0, 11)
    h3 = rotl((((h3 + w1) | 0) ^ h1) | 0, 13)
    h4 = rotl((((h4 ^ w1) | 0) + h2) | 0, 17)
  }
  h1 = (h1 ^ len) | 0
  h2 = (h2 ^ h1) | 0
  h3 = (h3 + h2) | 0
  h4 = (h4 ^ h3) | 0
  h1 = rotl(h1, 9)
  h2 = rotl(h2, 13)
  h3 = rotl(h3, 17)
  h4 = rotl(h4, 19)
  h1 = (h1 + h3) | 0
  h2 = (h2 ^ h4) | 0
  h3 = (h3 + h1) | 0
  h4 = (h4 ^ h2) | 0
  const out: ByteArray = []
  for (const h of [h1 >>> 0, h2 >>> 0, h3 >>> 0, h4 >>> 0]) {
    out.push(h & 255, (h >>> 8) & 255, (h >>> 16) & 255, (h >>> 24) & 255)
  }
  return out
}

// ---------------------------------------------------------------- 密钥流（上游 JSON 资产，原样读取）

let KEYSTREAM: ByteArray | null = null
let MNS0101_KEYSTREAM: ByteArray | null = null

function loadKeystream(file: string): ByteArray {
  const j = JSON.parse(readFileSync(staticFile('xhs', `xhs_core/js/${file}`), 'utf8')) as { b64: string }
  return [...Buffer.from(j.b64, 'base64')]
}

function keystream(): ByteArray {
  return (KEYSTREAM ??= loadKeystream('mns_keystreams.json'))
}

function keystream0101(): ByteArray {
  return (MNS0101_KEYSTREAM ??= loadKeystream('mns_0101_keystream.json'))
}

// ---------------------------------------------------------------- pack

export interface PackParams {
  api: string
  data?: string
  a1: string
  appId?: string
  deviceTag?: string
  dsn?: string
  dsSigBytes?: ByteArray | Uint8Array
  version: number
  ts: number
  loadts: number
  seq: number | string
  envConst: number | string
  envFpTail: number[]
  md5FullBytes?: ByteArray
  md5UrlBytes?: ByteArray
  fullLen?: number
}

function envFp(versionKey: number, tail: number[]): ByteArray {
  if (!Array.isArray(tail) || tail.length !== 14) {
    throw new Error('envFpTail required (14 bytes)')
  }
  return [1, versionKey ^ 115].concat(tail)
}

function packPlaintext(p: PackParams): ByteArray {
  if (p.loadts == null) throw new Error('mns loadts required')
  if (p.seq == null) throw new Error('mns seq required')
  if (p.envConst == null) throw new Error('mns envConst required')
  if (!Array.isArray(p.envFpTail) || p.envFpTail.length !== 14) {
    throw new Error('mns envFpTail required (14 bytes)')
  }
  const version = (Number(p.version) >>> 0)
  const vKey = version & 255
  const ts = p.ts
  const loadts = p.loadts
  const appId = String(p.appId || 'xhs-pc-web')
  const deviceTag = String(p.deviceTag || p.dsn || 'a3')
  const full = String(p.api) + (p.data || '')
  const md5full = p.md5FullBytes ? [...p.md5FullBytes] : md5Bytes(full)
  const md5api = p.md5UrlBytes ? [...p.md5UrlBytes] : md5Bytes(p.api)
  // DS 脚本尚未就绪时 window._dsn = "nop"，尾部直接放 MD5(url) XOR versionLowByte；
  // DS 就绪后 PC/Creator 分别使用 a3/a1，尾部为 _dsf(null, timestamp || MD5(url)) XOR versionLowByte。
  // Creator 的 _dsf 来自服务端 DS 程序，经 dsSigBytes 显式传入；本地 dsf() 仅保留给已静态提纯的路径。
  let rawDsSig: ByteArray
  if (deviceTag === 'nop') {
    rawDsSig = md5api
  } else if (Array.isArray(p.dsSigBytes) || ArrayBuffer.isView(p.dsSigBytes)) {
    rawDsSig = Array.from(p.dsSigBytes as ArrayLike<number>)
    if (rawDsSig.length !== 16) throw new Error('mns dsSigBytes must be 16 bytes')
  } else {
    rawDsSig = dsf(le64(ts).concat(md5api))
  }
  const dsSig = rawDsSig.map((b) => b ^ vKey)

  const out: ByteArray = []
  const push = (a: ArrayLike<number>): void => {
    for (let i = 0; i < a.length; i++) out.push(a[i]!)
  }
  push([121, 104, 96, 41])
  push(le32(version))
  push(le64(ts))
  push(le64(loadts))
  push(le32(Number(p.seq) >>> 0))
  push(le32(Number(p.envConst) >>> 0))
  push(le32(p.fullLen != null ? Number(p.fullLen) >>> 0 : Buffer.byteLength(full, 'utf8')))
  push(md5full.slice(0, 8).map((b) => b ^ vKey))
  push([p.a1.length])
  push(strBytes(p.a1))
  const appBytes = strBytes(appId)
  if (appBytes.length > 255) throw new Error('mns appId too long')
  push([appBytes.length])
  push(appBytes)
  push(envFp(vKey, p.envFpTail))
  const tagBytes = strBytes(deviceTag)
  if (tagBytes.length > 255) throw new Error('mns deviceTag too long')
  push([tagBytes.length])
  push(tagBytes)
  push([16])
  push(dsSig)
  return out
}

// ---------------------------------------------------------------- 三档签名

function sign0301(p: PackParams): string {
  const plain = packPlaintext(p)
  const ks = keystream()
  return 'mns0301_' + base64Custom(plain.map((b, i) => b ^ ks[i]!))
}

function sign0101(p: PackParams): string {
  const plain = packPlaintext(p)
  const ks = keystream0101()
  if (plain.length > ks.length) {
    throw new Error(`mns0101 keystream too short: ${ks.length} < ${plain.length}`)
  }
  return 'mns0101_' + base58Custom(plain.map((b, i) => b ^ ks[i]!))
}

// mns0201：XXTEA（自定义 DELTA）+ 同一自定义 base64 字母表。
// 真实密钥 = utf8("e6483ca2a1eed5e3")。
const MNS0201_DELTA = 1013904243
const MNS0201_KEY_STR = 'e6483ca2a1eed5e3'

function toWordsLE(bytes: ByteArray, includeLength: boolean): number[] {
  const e = bytes.length
  let a = e >> 2
  if (e & 3) a++
  const t = includeLength ? new Array<number>(a + 1).fill(0) : new Array<number>(a).fill(0)
  if (includeLength) t[a] = e
  for (let o = 0; o < e; o++) t[o >> 2] = (t[o >> 2] ?? 0) | (bytes[o]! << ((o & 3) << 3))
  return t
}

function fromWordsLE(r: number[], includeLength: boolean): number[] | null {
  const t = r.length
  let a = t << 2
  if (includeLength) {
    const e = r[t - 1]!
    a -= 4
    if (e < a - 3 || e > a) return null
    a = e
  }
  const f = new Array<number>(a)
  for (let i = 0; i < a; i++) f[i] = ((r[i >> 2] ?? 0) >>> ((i & 3) << 3)) & 0xff
  return f
}

function mnsKeyWords(): number[] {
  let kb = [...Buffer.from(MNS0201_KEY_STR, 'utf8')]
  if (kb.length < 16) kb = kb.concat(new Array(16 - kb.length).fill(0))
  return toWordsLE(kb, false)
}

function xxteaMx(sum: number, y: number, z: number, p: number, e: number, k: number[]): number {
  return ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e]! ^ z))) | 0
}

function xxteaEncrypt(v: number[], k: number[]): number[] {
  const n = v.length
  if (n < 2) return v
  const nn = n - 1
  let rounds = Math.floor(6 + 52 / n)
  let sum = 0
  let y: number
  let z = v[nn]!
  let e: number
  let p: number
  while (rounds-- > 0) {
    sum = (sum + MNS0201_DELTA) | 0
    e = (sum >>> 2) & 3
    for (p = 0; p < nn; p++) {
      y = v[p + 1]!
      z = v[p] = (v[p]! + xxteaMx(sum, y, z, p, e, k)) | 0
    }
    y = v[0]!
    z = v[nn] = (v[nn]! + xxteaMx(sum, y, z, nn, e, k)) | 0
  }
  return v
}

function encrypt0201(pack: ByteArray): number[] {
  const kw = mnsKeyWords()
  const dataWords = toWordsLE(pack, true)
  const cipherWords = xxteaEncrypt(dataWords.slice(), kw)
  return fromWordsLE(cipherWords, false) ?? []
}

function sign0201(p: PackParams): string {
  const plain = packPlaintext(p)
  return 'mns0201_' + base64Custom(encrypt0201(plain))
}

function signTier(p: PackParams, tier: string): string {
  switch (tier || '0301') {
    case '0101':
      return sign0101(p)
    case '0201':
      return sign0201(p)
    case '0301':
      return sign0301(p)
    default:
      throw new Error(`unsupported mns tier: ${tier}`)
  }
}

// ---------------------------------------------------------------- xs 信封

function encodeXs(x3: string, x4Value: string, options: Record<string, unknown>): string {
  // Browser's seccore_signv2 always sets x4 = (data ? typeof data : '')
  const signObj: Record<string, unknown> = {
    x0: String(options.signVersion || '4.4.3'),
    x1: String(options.appId || 'xhs-pc-web'),
    x2: String(options.platform || 'Windows'),
    x3,
    x4: x4Value,
  }
  // Current PC envelopes append x5 and, after webSsk activation, x6/x7.
  // Creator 4.3.6 envelopes stop at x4.
  if (options.x5 != null) signObj.x5 = String(options.x5)
  if (options.x6 != null) signObj.x6 = options.x6
  if (options.x7 != null) signObj.x7 = options.x7
  return 'XYS_' + b64XS(encodeUtf8(JSON.stringify(signObj)))
}

function parseWebSsk(value: unknown, appId: string): Buffer | null {
  let storage: unknown = value
  if (typeof storage === 'string') {
    if (!storage) return null
    try {
      storage = JSON.parse(storage)
    } catch {
      return null
    }
  }
  if (!storage || typeof storage !== 'object') return null
  const encoded = (storage as Record<string, unknown>)[appId]
  if (typeof encoded !== 'string' || !encoded) return null
  const raw = Buffer.from(encoded, 'base64')
  return raw.length >= 32 ? raw : null
}

interface SskSign {
  encSskSign: Record<string, string>
  encSsk: Record<string, string>
}

function buildEncSskSign(
  md5FullBytes: ByteArray,
  webSsk: unknown,
  appId: string,
  options: Record<string, unknown>,
  det: (() => number) | null,
): SskSign | null {
  const secret = parseWebSsk(webSsk, appId)
  if (!secret) return null
  const nonce = Buffer.alloc(4)
  const randomValue = options.sskRandom != null ? Number(options.sskRandom) >>> 0 : randU32LE(det)
  const timestamp = options.sskTimestamp != null ? Number(options.sskTimestamp) >>> 0 : randNow() >>> 0
  nonce.writeUInt32LE((timestamp + randomValue) >>> 0, 0)
  const digest = createHash('sha1').update(Buffer.concat([secret, nonce])).digest()
  const encSsk = Buffer.concat([nonce, digest, secret.subarray(32)])
  const encSskSign = createHash('sha1').update(Buffer.concat([Buffer.from(md5FullBytes), encSsk])).digest('base64')
  return {
    encSskSign: { [appId]: encSskSign },
    encSsk: { [appId]: encSsk.toString('base64') },
  }
}

// ---------------------------------------------------------------- X-S-Common

const _crcTable: number[] = (() => {
  const a = 0xedb88320
  const s = new Array<number>(256)
  for (let d = 0; d < 256; d++) {
    let r = d
    for (let c = 8; c > 0; c--) r = 1 & r ? (r >>> 1) ^ a : r >>> 1
    s[d] = r >>> 0
  }
  return s
})()

function gens9(str: string): number {
  const a = 0xedb88320
  let c = -1
  for (let r = 0; r < str.length; r++) {
    c = _crcTable[(255 & c) ^ str.charCodeAt(r)]! ^ (c >>> 8)
  }
  return (-1 ^ c ^ a) | 0
}

function xsCommon(a1: string, xt: string, xs: string, dslPair: string, b1: string, options: Record<string, unknown>): string {
  if (b1 == null) throw new Error('xsCommon: b1 必须显式传入（允许空字符串）')
  if (!dslPair) throw new Error('xsCommon: dslPair 必传')
  const b1Value = String(b1)
  const webBuild = String(options.webBuild || '6.47.2')
  const coldB1 = b1Value === ''
  const d: Record<string, unknown> = {
    s0: 5,
    s1: '',
    x0: String(options.b1b1 || '1'),
    x1: String(options.signVersion || '4.4.3'),
    x2: String(options.platform || 'Windows'),
    x3: String(options.appId || 'xhs-pc-web'),
    x4: webBuild,
    x5: a1,
    x6: '',
    x7: '',
    x8: coldB1 ? null : b1Value,
    x9: gens9(coldB1 ? 'null' : b1Value),
    x10: Number(options.signCount || 0),
    x11: 'normal',
    x12: dslPair,
  }
  return b64XS(encodeUtf8(JSON.stringify(d)))
}

// ---------------------------------------------------------------- 服务端下发的 DS 程序（动态代码，仍走隔离 vm）

function runDsfProgram(program: unknown, inputBytes: ByteArray, timeoutMs?: number): ByteArray {
  const source = String(program || '')
  if (!source || (!source.includes('__$c') && !source.includes('_dsf'))) {
    throw new Error('Creator DS program is missing or invalid')
  }
  const sandbox: Record<string, unknown> = {}
  sandbox.global = sandbox
  vm.runInNewContext(source, sandbox, { timeout: timeoutMs != null ? Number(timeoutMs) : 10000 })
  const dsfFn = sandbox._dsf
  if (typeof dsfFn !== 'function') {
    throw new Error('Creator _dsf did not export _dsf')
  }
  const output = Array.from(
    (dsfFn as (a: null, b: ByteArray) => ArrayLike<unknown>)(null, Array.from(inputBytes || [])) || [],
  )
  if (output.length !== 16 || output.some((byte) => !Number.isInteger(byte) || (byte as number) < 0 || (byte as number) > 255)) {
    throw new Error('Creator _dsf output must be 16 bytes')
  }
  return output as ByteArray
}

// ---------------------------------------------------------------- signFull（与上游 sign.js 同输入输出）

export interface NativeSignResult {
  x3: string
  xs: string
  xt: string
  xs_common?: string
  len: number
  prefix: string
  tier: string
  pure: boolean
}

/** mns + X-s + X-t（+ X-S-Common，给了 dslPair 时）。入参与上游 sign.js 的 signFull 相同。 */
export function signFull(input: Record<string, unknown>): NativeSignResult {
  const det = freshDet()
  const src = input || {}
  if (!src.cookie) throw new Error('cookie required (must be passed via CLI JSON)')
  const cookie = String(src.cookie)
  const cookieMap = Object.fromEntries(
    cookie.split(/;\s*/).map((part) => {
      const offset = part.indexOf('=')
      return offset < 0 ? [part, ''] : [part.slice(0, offset), part.slice(offset + 1)]
    }),
  )
  const a1 = (cookie.match(/a1=([^;]*)/) || [])[1] || ''
  if (!a1) throw new Error('cookie a1 required')
  const now = src.now != null ? Number(src.now) : randNow()
  const version = src.version != null ? Number(src.version) >>> 0 : Math.floor(randFloat(det) * 0x100000000) >>> 0
  const loadts = src.loadts != null ? Number(src.loadts) : Number(cookieMap.loadts)
  if (!Number.isFinite(loadts)) throw new Error('loadts required (input.loadts or cookie loadts)')
  if (src.seq == null) throw new Error('seq required from PcDeviceProfile session state')
  if (src.envConst == null) throw new Error('envConst required from PcDeviceProfile stage state')
  if (!Array.isArray(src.envFpTail) || (src.envFpTail as unknown[]).length !== 14) {
    throw new Error('envFpTail required from PcDeviceProfile stage state (14 bytes)')
  }
  // seccore_signv2 receives `data` as JS object or string (not stringified for u calc)
  const dataIn = src.data
  const dataStr = dataIn == null ? '' : typeof dataIn === 'object' ? JSON.stringify(dataIn) : String(dataIn)
  const c = String(src.api) + dataStr
  // x4 label per browser: object data → 'object', string data (non-empty) → 'string', else ''
  const x4Label = dataIn == null || dataIn === '' ? '' : typeof dataIn === 'object' ? 'object' : 'string'
  const md5Full = hexToBytes(createHash('md5').update(c, 'utf8').digest('hex'))
  const md5Url = hexToBytes(createHash('md5').update(String(src.api), 'utf8').digest('hex'))
  const fullLen = Buffer.byteLength(c, 'utf8')
  const tier = String(src.tier || '0301')
  const deviceTag = String(src.deviceTag || src.dsn || 'a3')
  let dsSigBytes = src.dsSigBytes as ByteArray | Uint8Array | undefined
  // Creator's Python adapter historically called this context field
  // ``dsProgram`` while the standalone signer used ``dsfProgram``.
  const dsfProgram = src.dsfProgram || src.dsProgram
  if (deviceTag !== 'nop' && !dsSigBytes && dsfProgram) {
    const dsfInput = le64(now).concat(md5Url)
    dsSigBytes = runDsfProgram(dsfProgram, dsfInput, src.dsfTimeoutMs == null ? undefined : Number(src.dsfTimeoutMs))
  }
  const x3 = signTier(
    {
      api: String(src.api),
      data: dataStr,
      a1,
      appId: String(src.appId || 'xhs-pc-web'),
      deviceTag,
      dsSigBytes,
      version,
      ts: now,
      loadts,
      seq: src.seq as number | string,
      envConst: src.envConst as number | string,
      envFpTail: src.envFpTail as number[],
      md5FullBytes: md5Full,
      md5UrlBytes: md5Url,
      fullLen,
    },
    tier,
  )
  const xsOptions: Record<string, unknown> = { ...src }
  const appId = String(src.appId || 'xhs-pc-web')
  if (appId === 'xhs-pc-web') {
    xsOptions.x5 = Buffer.from(md5Full).toString('hex')
    const ssk = buildEncSskSign(md5Full, src.webSsk, appId, src, det)
    if (ssk) {
      xsOptions.x6 = ssk.encSskSign
      xsOptions.x7 = ssk.encSsk
    } else {
      delete xsOptions.x6
      delete xsOptions.x7
    }
  } else {
    delete xsOptions.x5
    delete xsOptions.x6
    delete xsOptions.x7
  }
  const xs = encodeXs(x3, x4Label, xsOptions)
  // Browser builds MNS first, then samples Date.now() again for X-t.
  const xt = src.xt != null ? String(src.xt) : String(randNow())
  const out: NativeSignResult = { x3, xs, xt, len: x3.length, prefix: x3.slice(0, 12), tier, pure: true }
  // X-S-Common 纯算（需 b1 + dslPair）
  const b1 = src.b1 == null ? '' : String(src.b1)
  const dslPairRaw = src.dslPair == null ? (src as Record<string, unknown>).dsl_pair : src.dslPair
  const dslPair = dslPairRaw == null ? '' : String(dslPairRaw)
  if (dslPair) {
    const webBuild = String(src.webBuild || cookieMap.webBuild || '')
    if (!webBuild) throw new Error('webBuild required (input.webBuild or cookie webBuild)')
    out.xs_common = xsCommon(a1, xt, xs, dslPair, b1, {
      b1b1: src.b1b1,
      signVersion: src.signVersion,
      platform: src.platform,
      appId: src.appId,
      webBuild,
      signCount: src.signCount,
    })
  }
  return out
}
