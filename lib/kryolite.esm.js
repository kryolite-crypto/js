import require$$0 from 'crypto';

var commonjsGlobal = typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

function getDefaultExportFromCjs (x) {
	return x && x.__esModule && Object.prototype.hasOwnProperty.call(x, 'default') ? x['default'] : x;
}

var build = {};

var address = {};

var lib = {};

(function (exports) {
	/*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.utils = exports.curve25519 = exports.getSharedSecret = exports.sync = exports.verify = exports.sign = exports.getPublicKey = exports.Signature = exports.Point = exports.RistrettoPoint = exports.ExtendedPoint = exports.CURVE = void 0;
	const nodeCrypto = require$$0;
	const _0n = BigInt(0);
	const _1n = BigInt(1);
	const _2n = BigInt(2);
	const _8n = BigInt(8);
	const CU_O = BigInt('7237005577332262213973186563042994240857116359379907606001950938285454250989');
	const CURVE = Object.freeze({
	    a: BigInt(-1),
	    d: BigInt('37095705934669439343138083508754565189542113879843219016388785533085940283555'),
	    P: BigInt('57896044618658097711785492504343953926634992332820282019728792003956564819949'),
	    l: CU_O,
	    n: CU_O,
	    h: BigInt(8),
	    Gx: BigInt('15112221349535400772501151409588531511454012693041857206046113283949847762202'),
	    Gy: BigInt('46316835694926478169428394003475163141307993866256225615783033603165251855960'),
	});
	exports.CURVE = CURVE;
	const POW_2_256 = BigInt('0x10000000000000000000000000000000000000000000000000000000000000000');
	const SQRT_M1 = BigInt('19681161376707505956807079304988542015446066515923890162744021073123829784752');
	BigInt('6853475219497561581579357271197624642482790079785650197046958215289687604742');
	const SQRT_AD_MINUS_ONE = BigInt('25063068953384623474111414158702152701244531502492656460079210482610430750235');
	const INVSQRT_A_MINUS_D = BigInt('54469307008909316920995813868745141605393597292927456921205312896311721017578');
	const ONE_MINUS_D_SQ = BigInt('1159843021668779879193775521855586647937357759715417654439879720876111806838');
	const D_MINUS_ONE_SQ = BigInt('40440834346308536858101042469323190826248399146238708352240133220865137265952');
	class ExtendedPoint {
	    constructor(x, y, z, t) {
	        this.x = x;
	        this.y = y;
	        this.z = z;
	        this.t = t;
	    }
	    static fromAffine(p) {
	        if (!(p instanceof Point)) {
	            throw new TypeError('ExtendedPoint#fromAffine: expected Point');
	        }
	        if (p.equals(Point.ZERO))
	            return ExtendedPoint.ZERO;
	        return new ExtendedPoint(p.x, p.y, _1n, mod(p.x * p.y));
	    }
	    static toAffineBatch(points) {
	        const toInv = invertBatch(points.map((p) => p.z));
	        return points.map((p, i) => p.toAffine(toInv[i]));
	    }
	    static normalizeZ(points) {
	        return this.toAffineBatch(points).map(this.fromAffine);
	    }
	    equals(other) {
	        assertExtPoint(other);
	        const { x: X1, y: Y1, z: Z1 } = this;
	        const { x: X2, y: Y2, z: Z2 } = other;
	        const X1Z2 = mod(X1 * Z2);
	        const X2Z1 = mod(X2 * Z1);
	        const Y1Z2 = mod(Y1 * Z2);
	        const Y2Z1 = mod(Y2 * Z1);
	        return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
	    }
	    negate() {
	        return new ExtendedPoint(mod(-this.x), this.y, this.z, mod(-this.t));
	    }
	    double() {
	        const { x: X1, y: Y1, z: Z1 } = this;
	        const { a } = CURVE;
	        const A = mod(X1 * X1);
	        const B = mod(Y1 * Y1);
	        const C = mod(_2n * mod(Z1 * Z1));
	        const D = mod(a * A);
	        const x1y1 = X1 + Y1;
	        const E = mod(mod(x1y1 * x1y1) - A - B);
	        const G = D + B;
	        const F = G - C;
	        const H = D - B;
	        const X3 = mod(E * F);
	        const Y3 = mod(G * H);
	        const T3 = mod(E * H);
	        const Z3 = mod(F * G);
	        return new ExtendedPoint(X3, Y3, Z3, T3);
	    }
	    add(other) {
	        assertExtPoint(other);
	        const { x: X1, y: Y1, z: Z1, t: T1 } = this;
	        const { x: X2, y: Y2, z: Z2, t: T2 } = other;
	        const A = mod((Y1 - X1) * (Y2 + X2));
	        const B = mod((Y1 + X1) * (Y2 - X2));
	        const F = mod(B - A);
	        if (F === _0n)
	            return this.double();
	        const C = mod(Z1 * _2n * T2);
	        const D = mod(T1 * _2n * Z2);
	        const E = D + C;
	        const G = B + A;
	        const H = D - C;
	        const X3 = mod(E * F);
	        const Y3 = mod(G * H);
	        const T3 = mod(E * H);
	        const Z3 = mod(F * G);
	        return new ExtendedPoint(X3, Y3, Z3, T3);
	    }
	    subtract(other) {
	        return this.add(other.negate());
	    }
	    precomputeWindow(W) {
	        const windows = 1 + 256 / W;
	        const points = [];
	        let p = this;
	        let base = p;
	        for (let window = 0; window < windows; window++) {
	            base = p;
	            points.push(base);
	            for (let i = 1; i < 2 ** (W - 1); i++) {
	                base = base.add(p);
	                points.push(base);
	            }
	            p = base.double();
	        }
	        return points;
	    }
	    wNAF(n, affinePoint) {
	        if (!affinePoint && this.equals(ExtendedPoint.BASE))
	            affinePoint = Point.BASE;
	        const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
	        if (256 % W) {
	            throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2');
	        }
	        let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
	        if (!precomputes) {
	            precomputes = this.precomputeWindow(W);
	            if (affinePoint && W !== 1) {
	                precomputes = ExtendedPoint.normalizeZ(precomputes);
	                pointPrecomputes.set(affinePoint, precomputes);
	            }
	        }
	        let p = ExtendedPoint.ZERO;
	        let f = ExtendedPoint.BASE;
	        const windows = 1 + 256 / W;
	        const windowSize = 2 ** (W - 1);
	        const mask = BigInt(2 ** W - 1);
	        const maxNumber = 2 ** W;
	        const shiftBy = BigInt(W);
	        for (let window = 0; window < windows; window++) {
	            const offset = window * windowSize;
	            let wbits = Number(n & mask);
	            n >>= shiftBy;
	            if (wbits > windowSize) {
	                wbits -= maxNumber;
	                n += _1n;
	            }
	            const offset1 = offset;
	            const offset2 = offset + Math.abs(wbits) - 1;
	            const cond1 = window % 2 !== 0;
	            const cond2 = wbits < 0;
	            if (wbits === 0) {
	                f = f.add(constTimeNegate(cond1, precomputes[offset1]));
	            }
	            else {
	                p = p.add(constTimeNegate(cond2, precomputes[offset2]));
	            }
	        }
	        return ExtendedPoint.normalizeZ([p, f])[0];
	    }
	    multiply(scalar, affinePoint) {
	        return this.wNAF(normalizeScalar(scalar, CURVE.l), affinePoint);
	    }
	    multiplyUnsafe(scalar) {
	        let n = normalizeScalar(scalar, CURVE.l, false);
	        const G = ExtendedPoint.BASE;
	        const P0 = ExtendedPoint.ZERO;
	        if (n === _0n)
	            return P0;
	        if (this.equals(P0) || n === _1n)
	            return this;
	        if (this.equals(G))
	            return this.wNAF(n);
	        let p = P0;
	        let d = this;
	        while (n > _0n) {
	            if (n & _1n)
	                p = p.add(d);
	            d = d.double();
	            n >>= _1n;
	        }
	        return p;
	    }
	    isSmallOrder() {
	        return this.multiplyUnsafe(CURVE.h).equals(ExtendedPoint.ZERO);
	    }
	    isTorsionFree() {
	        let p = this.multiplyUnsafe(CURVE.l / _2n).double();
	        if (CURVE.l % _2n)
	            p = p.add(this);
	        return p.equals(ExtendedPoint.ZERO);
	    }
	    toAffine(invZ) {
	        const { x, y, z } = this;
	        const is0 = this.equals(ExtendedPoint.ZERO);
	        if (invZ == null)
	            invZ = is0 ? _8n : invert(z);
	        const ax = mod(x * invZ);
	        const ay = mod(y * invZ);
	        const zz = mod(z * invZ);
	        if (is0)
	            return Point.ZERO;
	        if (zz !== _1n)
	            throw new Error('invZ was invalid');
	        return new Point(ax, ay);
	    }
	    fromRistrettoBytes() {
	        legacyRist();
	    }
	    toRistrettoBytes() {
	        legacyRist();
	    }
	    fromRistrettoHash() {
	        legacyRist();
	    }
	}
	exports.ExtendedPoint = ExtendedPoint;
	ExtendedPoint.BASE = new ExtendedPoint(CURVE.Gx, CURVE.Gy, _1n, mod(CURVE.Gx * CURVE.Gy));
	ExtendedPoint.ZERO = new ExtendedPoint(_0n, _1n, _1n, _0n);
	function constTimeNegate(condition, item) {
	    const neg = item.negate();
	    return condition ? neg : item;
	}
	function assertExtPoint(other) {
	    if (!(other instanceof ExtendedPoint))
	        throw new TypeError('ExtendedPoint expected');
	}
	function assertRstPoint(other) {
	    if (!(other instanceof RistrettoPoint))
	        throw new TypeError('RistrettoPoint expected');
	}
	function legacyRist() {
	    throw new Error('Legacy method: switch to RistrettoPoint');
	}
	class RistrettoPoint {
	    constructor(ep) {
	        this.ep = ep;
	    }
	    static calcElligatorRistrettoMap(r0) {
	        const { d } = CURVE;
	        const r = mod(SQRT_M1 * r0 * r0);
	        const Ns = mod((r + _1n) * ONE_MINUS_D_SQ);
	        let c = BigInt(-1);
	        const D = mod((c - d * r) * mod(r + d));
	        let { isValid: Ns_D_is_sq, value: s } = uvRatio(Ns, D);
	        let s_ = mod(s * r0);
	        if (!edIsNegative(s_))
	            s_ = mod(-s_);
	        if (!Ns_D_is_sq)
	            s = s_;
	        if (!Ns_D_is_sq)
	            c = r;
	        const Nt = mod(c * (r - _1n) * D_MINUS_ONE_SQ - D);
	        const s2 = s * s;
	        const W0 = mod((s + s) * D);
	        const W1 = mod(Nt * SQRT_AD_MINUS_ONE);
	        const W2 = mod(_1n - s2);
	        const W3 = mod(_1n + s2);
	        return new ExtendedPoint(mod(W0 * W3), mod(W2 * W1), mod(W1 * W3), mod(W0 * W2));
	    }
	    static hashToCurve(hex) {
	        hex = ensureBytes(hex, 64);
	        const r1 = bytes255ToNumberLE(hex.slice(0, 32));
	        const R1 = this.calcElligatorRistrettoMap(r1);
	        const r2 = bytes255ToNumberLE(hex.slice(32, 64));
	        const R2 = this.calcElligatorRistrettoMap(r2);
	        return new RistrettoPoint(R1.add(R2));
	    }
	    static fromHex(hex) {
	        hex = ensureBytes(hex, 32);
	        const { a, d } = CURVE;
	        const emsg = 'RistrettoPoint.fromHex: the hex is not valid encoding of RistrettoPoint';
	        const s = bytes255ToNumberLE(hex);
	        if (!equalBytes(numberTo32BytesLE(s), hex) || edIsNegative(s))
	            throw new Error(emsg);
	        const s2 = mod(s * s);
	        const u1 = mod(_1n + a * s2);
	        const u2 = mod(_1n - a * s2);
	        const u1_2 = mod(u1 * u1);
	        const u2_2 = mod(u2 * u2);
	        const v = mod(a * d * u1_2 - u2_2);
	        const { isValid, value: I } = invertSqrt(mod(v * u2_2));
	        const Dx = mod(I * u2);
	        const Dy = mod(I * Dx * v);
	        let x = mod((s + s) * Dx);
	        if (edIsNegative(x))
	            x = mod(-x);
	        const y = mod(u1 * Dy);
	        const t = mod(x * y);
	        if (!isValid || edIsNegative(t) || y === _0n)
	            throw new Error(emsg);
	        return new RistrettoPoint(new ExtendedPoint(x, y, _1n, t));
	    }
	    toRawBytes() {
	        let { x, y, z, t } = this.ep;
	        const u1 = mod(mod(z + y) * mod(z - y));
	        const u2 = mod(x * y);
	        const u2sq = mod(u2 * u2);
	        const { value: invsqrt } = invertSqrt(mod(u1 * u2sq));
	        const D1 = mod(invsqrt * u1);
	        const D2 = mod(invsqrt * u2);
	        const zInv = mod(D1 * D2 * t);
	        let D;
	        if (edIsNegative(t * zInv)) {
	            let _x = mod(y * SQRT_M1);
	            let _y = mod(x * SQRT_M1);
	            x = _x;
	            y = _y;
	            D = mod(D1 * INVSQRT_A_MINUS_D);
	        }
	        else {
	            D = D2;
	        }
	        if (edIsNegative(x * zInv))
	            y = mod(-y);
	        let s = mod((z - y) * D);
	        if (edIsNegative(s))
	            s = mod(-s);
	        return numberTo32BytesLE(s);
	    }
	    toHex() {
	        return bytesToHex(this.toRawBytes());
	    }
	    toString() {
	        return this.toHex();
	    }
	    equals(other) {
	        assertRstPoint(other);
	        const a = this.ep;
	        const b = other.ep;
	        const one = mod(a.x * b.y) === mod(a.y * b.x);
	        const two = mod(a.y * b.y) === mod(a.x * b.x);
	        return one || two;
	    }
	    add(other) {
	        assertRstPoint(other);
	        return new RistrettoPoint(this.ep.add(other.ep));
	    }
	    subtract(other) {
	        assertRstPoint(other);
	        return new RistrettoPoint(this.ep.subtract(other.ep));
	    }
	    multiply(scalar) {
	        return new RistrettoPoint(this.ep.multiply(scalar));
	    }
	    multiplyUnsafe(scalar) {
	        return new RistrettoPoint(this.ep.multiplyUnsafe(scalar));
	    }
	}
	exports.RistrettoPoint = RistrettoPoint;
	RistrettoPoint.BASE = new RistrettoPoint(ExtendedPoint.BASE);
	RistrettoPoint.ZERO = new RistrettoPoint(ExtendedPoint.ZERO);
	const pointPrecomputes = new WeakMap();
	class Point {
	    constructor(x, y) {
	        this.x = x;
	        this.y = y;
	    }
	    _setWindowSize(windowSize) {
	        this._WINDOW_SIZE = windowSize;
	        pointPrecomputes.delete(this);
	    }
	    static fromHex(hex, strict = true) {
	        const { d, P } = CURVE;
	        hex = ensureBytes(hex, 32);
	        const normed = hex.slice();
	        normed[31] = hex[31] & ~0x80;
	        const y = bytesToNumberLE(normed);
	        if (strict && y >= P)
	            throw new Error('Expected 0 < hex < P');
	        if (!strict && y >= POW_2_256)
	            throw new Error('Expected 0 < hex < 2**256');
	        const y2 = mod(y * y);
	        const u = mod(y2 - _1n);
	        const v = mod(d * y2 + _1n);
	        let { isValid, value: x } = uvRatio(u, v);
	        if (!isValid)
	            throw new Error('Point.fromHex: invalid y coordinate');
	        const isXOdd = (x & _1n) === _1n;
	        const isLastByteOdd = (hex[31] & 0x80) !== 0;
	        if (isLastByteOdd !== isXOdd) {
	            x = mod(-x);
	        }
	        return new Point(x, y);
	    }
	    static async fromPrivateKey(privateKey) {
	        return (await getExtendedPublicKey(privateKey)).point;
	    }
	    toRawBytes() {
	        const bytes = numberTo32BytesLE(this.y);
	        bytes[31] |= this.x & _1n ? 0x80 : 0;
	        return bytes;
	    }
	    toHex() {
	        return bytesToHex(this.toRawBytes());
	    }
	    toX25519() {
	        const { y } = this;
	        const u = mod((_1n + y) * invert(_1n - y));
	        return numberTo32BytesLE(u);
	    }
	    isTorsionFree() {
	        return ExtendedPoint.fromAffine(this).isTorsionFree();
	    }
	    equals(other) {
	        return this.x === other.x && this.y === other.y;
	    }
	    negate() {
	        return new Point(mod(-this.x), this.y);
	    }
	    add(other) {
	        return ExtendedPoint.fromAffine(this).add(ExtendedPoint.fromAffine(other)).toAffine();
	    }
	    subtract(other) {
	        return this.add(other.negate());
	    }
	    multiply(scalar) {
	        return ExtendedPoint.fromAffine(this).multiply(scalar, this).toAffine();
	    }
	}
	exports.Point = Point;
	Point.BASE = new Point(CURVE.Gx, CURVE.Gy);
	Point.ZERO = new Point(_0n, _1n);
	class Signature {
	    constructor(r, s) {
	        this.r = r;
	        this.s = s;
	        this.assertValidity();
	    }
	    static fromHex(hex) {
	        const bytes = ensureBytes(hex, 64);
	        const r = Point.fromHex(bytes.slice(0, 32), false);
	        const s = bytesToNumberLE(bytes.slice(32, 64));
	        return new Signature(r, s);
	    }
	    assertValidity() {
	        const { r, s } = this;
	        if (!(r instanceof Point))
	            throw new Error('Expected Point instance');
	        normalizeScalar(s, CURVE.l, false);
	        return this;
	    }
	    toRawBytes() {
	        const u8 = new Uint8Array(64);
	        u8.set(this.r.toRawBytes());
	        u8.set(numberTo32BytesLE(this.s), 32);
	        return u8;
	    }
	    toHex() {
	        return bytesToHex(this.toRawBytes());
	    }
	}
	exports.Signature = Signature;
	function concatBytes(...arrays) {
	    if (!arrays.every((a) => a instanceof Uint8Array))
	        throw new Error('Expected Uint8Array list');
	    if (arrays.length === 1)
	        return arrays[0];
	    const length = arrays.reduce((a, arr) => a + arr.length, 0);
	    const result = new Uint8Array(length);
	    for (let i = 0, pad = 0; i < arrays.length; i++) {
	        const arr = arrays[i];
	        result.set(arr, pad);
	        pad += arr.length;
	    }
	    return result;
	}
	const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
	function bytesToHex(uint8a) {
	    if (!(uint8a instanceof Uint8Array))
	        throw new Error('Uint8Array expected');
	    let hex = '';
	    for (let i = 0; i < uint8a.length; i++) {
	        hex += hexes[uint8a[i]];
	    }
	    return hex;
	}
	function hexToBytes(hex) {
	    if (typeof hex !== 'string') {
	        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
	    }
	    if (hex.length % 2)
	        throw new Error('hexToBytes: received invalid unpadded hex');
	    const array = new Uint8Array(hex.length / 2);
	    for (let i = 0; i < array.length; i++) {
	        const j = i * 2;
	        const hexByte = hex.slice(j, j + 2);
	        const byte = Number.parseInt(hexByte, 16);
	        if (Number.isNaN(byte) || byte < 0)
	            throw new Error('Invalid byte sequence');
	        array[i] = byte;
	    }
	    return array;
	}
	function numberTo32BytesBE(num) {
	    const length = 32;
	    const hex = num.toString(16).padStart(length * 2, '0');
	    return hexToBytes(hex);
	}
	function numberTo32BytesLE(num) {
	    return numberTo32BytesBE(num).reverse();
	}
	function edIsNegative(num) {
	    return (mod(num) & _1n) === _1n;
	}
	function bytesToNumberLE(uint8a) {
	    if (!(uint8a instanceof Uint8Array))
	        throw new Error('Expected Uint8Array');
	    return BigInt('0x' + bytesToHex(Uint8Array.from(uint8a).reverse()));
	}
	const MAX_255B = BigInt('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
	function bytes255ToNumberLE(bytes) {
	    return mod(bytesToNumberLE(bytes) & MAX_255B);
	}
	function mod(a, b = CURVE.P) {
	    const res = a % b;
	    return res >= _0n ? res : b + res;
	}
	function invert(number, modulo = CURVE.P) {
	    if (number === _0n || modulo <= _0n) {
	        throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
	    }
	    let a = mod(number, modulo);
	    let b = modulo;
	    let x = _0n, u = _1n;
	    while (a !== _0n) {
	        const q = b / a;
	        const r = b % a;
	        const m = x - u * q;
	        b = a, a = r, x = u, u = m;
	    }
	    const gcd = b;
	    if (gcd !== _1n)
	        throw new Error('invert: does not exist');
	    return mod(x, modulo);
	}
	function invertBatch(nums, p = CURVE.P) {
	    const tmp = new Array(nums.length);
	    const lastMultiplied = nums.reduce((acc, num, i) => {
	        if (num === _0n)
	            return acc;
	        tmp[i] = acc;
	        return mod(acc * num, p);
	    }, _1n);
	    const inverted = invert(lastMultiplied, p);
	    nums.reduceRight((acc, num, i) => {
	        if (num === _0n)
	            return acc;
	        tmp[i] = mod(acc * tmp[i], p);
	        return mod(acc * num, p);
	    }, inverted);
	    return tmp;
	}
	function pow2(x, power) {
	    const { P } = CURVE;
	    let res = x;
	    while (power-- > _0n) {
	        res *= res;
	        res %= P;
	    }
	    return res;
	}
	function pow_2_252_3(x) {
	    const { P } = CURVE;
	    const _5n = BigInt(5);
	    const _10n = BigInt(10);
	    const _20n = BigInt(20);
	    const _40n = BigInt(40);
	    const _80n = BigInt(80);
	    const x2 = (x * x) % P;
	    const b2 = (x2 * x) % P;
	    const b4 = (pow2(b2, _2n) * b2) % P;
	    const b5 = (pow2(b4, _1n) * x) % P;
	    const b10 = (pow2(b5, _5n) * b5) % P;
	    const b20 = (pow2(b10, _10n) * b10) % P;
	    const b40 = (pow2(b20, _20n) * b20) % P;
	    const b80 = (pow2(b40, _40n) * b40) % P;
	    const b160 = (pow2(b80, _80n) * b80) % P;
	    const b240 = (pow2(b160, _80n) * b80) % P;
	    const b250 = (pow2(b240, _10n) * b10) % P;
	    const pow_p_5_8 = (pow2(b250, _2n) * x) % P;
	    return { pow_p_5_8, b2 };
	}
	function uvRatio(u, v) {
	    const v3 = mod(v * v * v);
	    const v7 = mod(v3 * v3 * v);
	    const pow = pow_2_252_3(u * v7).pow_p_5_8;
	    let x = mod(u * v3 * pow);
	    const vx2 = mod(v * x * x);
	    const root1 = x;
	    const root2 = mod(x * SQRT_M1);
	    const useRoot1 = vx2 === u;
	    const useRoot2 = vx2 === mod(-u);
	    const noRoot = vx2 === mod(-u * SQRT_M1);
	    if (useRoot1)
	        x = root1;
	    if (useRoot2 || noRoot)
	        x = root2;
	    if (edIsNegative(x))
	        x = mod(-x);
	    return { isValid: useRoot1 || useRoot2, value: x };
	}
	function invertSqrt(number) {
	    return uvRatio(_1n, number);
	}
	function modlLE(hash) {
	    return mod(bytesToNumberLE(hash), CURVE.l);
	}
	function equalBytes(b1, b2) {
	    if (b1.length !== b2.length) {
	        return false;
	    }
	    for (let i = 0; i < b1.length; i++) {
	        if (b1[i] !== b2[i]) {
	            return false;
	        }
	    }
	    return true;
	}
	function ensureBytes(hex, expectedLength) {
	    const bytes = hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes(hex);
	    if (typeof expectedLength === 'number' && bytes.length !== expectedLength)
	        throw new Error(`Expected ${expectedLength} bytes`);
	    return bytes;
	}
	function normalizeScalar(num, max, strict = true) {
	    if (!max)
	        throw new TypeError('Specify max value');
	    if (typeof num === 'number' && Number.isSafeInteger(num))
	        num = BigInt(num);
	    if (typeof num === 'bigint' && num < max) {
	        if (strict) {
	            if (_0n < num)
	                return num;
	        }
	        else {
	            if (_0n <= num)
	                return num;
	        }
	    }
	    throw new TypeError('Expected valid scalar: 0 < scalar < max');
	}
	function adjustBytes25519(bytes) {
	    bytes[0] &= 248;
	    bytes[31] &= 127;
	    bytes[31] |= 64;
	    return bytes;
	}
	function decodeScalar25519(n) {
	    return bytesToNumberLE(adjustBytes25519(ensureBytes(n, 32)));
	}
	function checkPrivateKey(key) {
	    key =
	        typeof key === 'bigint' || typeof key === 'number'
	            ? numberTo32BytesBE(normalizeScalar(key, POW_2_256))
	            : ensureBytes(key);
	    if (key.length !== 32)
	        throw new Error(`Expected 32 bytes`);
	    return key;
	}
	function getKeyFromHash(hashed) {
	    const head = adjustBytes25519(hashed.slice(0, 32));
	    const prefix = hashed.slice(32, 64);
	    const scalar = modlLE(head);
	    const point = Point.BASE.multiply(scalar);
	    const pointBytes = point.toRawBytes();
	    return { head, prefix, scalar, point, pointBytes };
	}
	let _sha512Sync;
	function sha512s(...m) {
	    if (typeof _sha512Sync !== 'function')
	        throw new Error('utils.sha512Sync must be set to use sync methods');
	    return _sha512Sync(...m);
	}
	async function getExtendedPublicKey(key) {
	    return getKeyFromHash(await exports.utils.sha512(checkPrivateKey(key)));
	}
	function getExtendedPublicKeySync(key) {
	    return getKeyFromHash(sha512s(checkPrivateKey(key)));
	}
	async function getPublicKey(privateKey) {
	    return (await getExtendedPublicKey(privateKey)).pointBytes;
	}
	exports.getPublicKey = getPublicKey;
	function getPublicKeySync(privateKey) {
	    return getExtendedPublicKeySync(privateKey).pointBytes;
	}
	async function sign(message, privateKey) {
	    message = ensureBytes(message);
	    const { prefix, scalar, pointBytes } = await getExtendedPublicKey(privateKey);
	    const r = modlLE(await exports.utils.sha512(prefix, message));
	    const R = Point.BASE.multiply(r);
	    const k = modlLE(await exports.utils.sha512(R.toRawBytes(), pointBytes, message));
	    const s = mod(r + k * scalar, CURVE.l);
	    return new Signature(R, s).toRawBytes();
	}
	exports.sign = sign;
	function signSync(message, privateKey) {
	    message = ensureBytes(message);
	    const { prefix, scalar, pointBytes } = getExtendedPublicKeySync(privateKey);
	    const r = modlLE(sha512s(prefix, message));
	    const R = Point.BASE.multiply(r);
	    const k = modlLE(sha512s(R.toRawBytes(), pointBytes, message));
	    const s = mod(r + k * scalar, CURVE.l);
	    return new Signature(R, s).toRawBytes();
	}
	function prepareVerification(sig, message, publicKey) {
	    message = ensureBytes(message);
	    if (!(publicKey instanceof Point))
	        publicKey = Point.fromHex(publicKey, false);
	    const { r, s } = sig instanceof Signature ? sig.assertValidity() : Signature.fromHex(sig);
	    const SB = ExtendedPoint.BASE.multiplyUnsafe(s);
	    return { r, s, SB, pub: publicKey, msg: message };
	}
	function finishVerification(publicKey, r, SB, hashed) {
	    const k = modlLE(hashed);
	    const kA = ExtendedPoint.fromAffine(publicKey).multiplyUnsafe(k);
	    const RkA = ExtendedPoint.fromAffine(r).add(kA);
	    return RkA.subtract(SB).multiplyUnsafe(CURVE.h).equals(ExtendedPoint.ZERO);
	}
	async function verify(sig, message, publicKey) {
	    const { r, SB, msg, pub } = prepareVerification(sig, message, publicKey);
	    const hashed = await exports.utils.sha512(r.toRawBytes(), pub.toRawBytes(), msg);
	    return finishVerification(pub, r, SB, hashed);
	}
	exports.verify = verify;
	function verifySync(sig, message, publicKey) {
	    const { r, SB, msg, pub } = prepareVerification(sig, message, publicKey);
	    const hashed = sha512s(r.toRawBytes(), pub.toRawBytes(), msg);
	    return finishVerification(pub, r, SB, hashed);
	}
	exports.sync = {
	    getExtendedPublicKey: getExtendedPublicKeySync,
	    getPublicKey: getPublicKeySync,
	    sign: signSync,
	    verify: verifySync,
	};
	async function getSharedSecret(privateKey, publicKey) {
	    const { head } = await getExtendedPublicKey(privateKey);
	    const u = Point.fromHex(publicKey).toX25519();
	    return exports.curve25519.scalarMult(head, u);
	}
	exports.getSharedSecret = getSharedSecret;
	Point.BASE._setWindowSize(8);
	function cswap(swap, x_2, x_3) {
	    const dummy = mod(swap * (x_2 - x_3));
	    x_2 = mod(x_2 - dummy);
	    x_3 = mod(x_3 + dummy);
	    return [x_2, x_3];
	}
	function montgomeryLadder(pointU, scalar) {
	    const { P } = CURVE;
	    const u = normalizeScalar(pointU, P);
	    const k = normalizeScalar(scalar, P);
	    const a24 = BigInt(121665);
	    const x_1 = u;
	    let x_2 = _1n;
	    let z_2 = _0n;
	    let x_3 = u;
	    let z_3 = _1n;
	    let swap = _0n;
	    let sw;
	    for (let t = BigInt(255 - 1); t >= _0n; t--) {
	        const k_t = (k >> t) & _1n;
	        swap ^= k_t;
	        sw = cswap(swap, x_2, x_3);
	        x_2 = sw[0];
	        x_3 = sw[1];
	        sw = cswap(swap, z_2, z_3);
	        z_2 = sw[0];
	        z_3 = sw[1];
	        swap = k_t;
	        const A = x_2 + z_2;
	        const AA = mod(A * A);
	        const B = x_2 - z_2;
	        const BB = mod(B * B);
	        const E = AA - BB;
	        const C = x_3 + z_3;
	        const D = x_3 - z_3;
	        const DA = mod(D * A);
	        const CB = mod(C * B);
	        const dacb = DA + CB;
	        const da_cb = DA - CB;
	        x_3 = mod(dacb * dacb);
	        z_3 = mod(x_1 * mod(da_cb * da_cb));
	        x_2 = mod(AA * BB);
	        z_2 = mod(E * (AA + mod(a24 * E)));
	    }
	    sw = cswap(swap, x_2, x_3);
	    x_2 = sw[0];
	    x_3 = sw[1];
	    sw = cswap(swap, z_2, z_3);
	    z_2 = sw[0];
	    z_3 = sw[1];
	    const { pow_p_5_8, b2 } = pow_2_252_3(z_2);
	    const xp2 = mod(pow2(pow_p_5_8, BigInt(3)) * b2);
	    return mod(x_2 * xp2);
	}
	function encodeUCoordinate(u) {
	    return numberTo32BytesLE(mod(u, CURVE.P));
	}
	function decodeUCoordinate(uEnc) {
	    const u = ensureBytes(uEnc, 32);
	    u[31] &= 127;
	    return bytesToNumberLE(u);
	}
	exports.curve25519 = {
	    BASE_POINT_U: '0900000000000000000000000000000000000000000000000000000000000000',
	    scalarMult(privateKey, publicKey) {
	        const u = decodeUCoordinate(publicKey);
	        const p = decodeScalar25519(privateKey);
	        const pu = montgomeryLadder(u, p);
	        if (pu === _0n)
	            throw new Error('Invalid private or public key received');
	        return encodeUCoordinate(pu);
	    },
	    scalarMultBase(privateKey) {
	        return exports.curve25519.scalarMult(privateKey, exports.curve25519.BASE_POINT_U);
	    },
	};
	const crypto = {
	    node: nodeCrypto,
	    web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
	};
	exports.utils = {
	    bytesToHex,
	    hexToBytes,
	    concatBytes,
	    getExtendedPublicKey,
	    mod,
	    invert,
	    TORSION_SUBGROUP: [
	        '0100000000000000000000000000000000000000000000000000000000000000',
	        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
	        '0000000000000000000000000000000000000000000000000000000000000080',
	        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
	        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
	        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
	        '0000000000000000000000000000000000000000000000000000000000000000',
	        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
	    ],
	    hashToPrivateScalar: (hash) => {
	        hash = ensureBytes(hash);
	        if (hash.length < 40 || hash.length > 1024)
	            throw new Error('Expected 40-1024 bytes of private key as per FIPS 186');
	        return mod(bytesToNumberLE(hash), CURVE.l - _1n) + _1n;
	    },
	    randomBytes: (bytesLength = 32) => {
	        if (crypto.web) {
	            return crypto.web.getRandomValues(new Uint8Array(bytesLength));
	        }
	        else if (crypto.node) {
	            const { randomBytes } = crypto.node;
	            return new Uint8Array(randomBytes(bytesLength).buffer);
	        }
	        else {
	            throw new Error("The environment doesn't have randomBytes function");
	        }
	    },
	    randomPrivateKey: () => {
	        return exports.utils.randomBytes(32);
	    },
	    sha512: async (...messages) => {
	        const message = concatBytes(...messages);
	        if (crypto.web) {
	            const buffer = await crypto.web.subtle.digest('SHA-512', message.buffer);
	            return new Uint8Array(buffer);
	        }
	        else if (crypto.node) {
	            return Uint8Array.from(crypto.node.createHash('sha512').update(message).digest());
	        }
	        else {
	            throw new Error("The environment doesn't have sha512 function");
	        }
	    },
	    precompute(windowSize = 8, point = Point.BASE) {
	        const cached = point.equals(Point.BASE) ? point : new Point(point.x, point.y);
	        cached._setWindowSize(windowSize);
	        cached.multiply(_2n);
	        return cached;
	    },
	    sha512Sync: undefined,
	};
	Object.defineProperties(exports.utils, {
	    sha512Sync: {
	        configurable: false,
	        get() {
	            return _sha512Sync;
	        },
	        set(val) {
	            if (!_sha512Sync)
	                _sha512Sync = val;
	        },
	    },
	});
} (lib));

var transaction = {};

var sha256 = {};

var _sha2 = {};

var _assert = {};

Object.defineProperty(_assert, "__esModule", { value: true });
_assert.output = _assert.exists = _assert.hash = _assert.bytes = _assert.bool = _assert.number = void 0;
function number(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(`Wrong positive integer: ${n}`);
}
_assert.number = number;
function bool(b) {
    if (typeof b !== 'boolean')
        throw new Error(`Expected boolean, not ${b}`);
}
_assert.bool = bool;
function bytes(b, ...lengths) {
    if (!(b instanceof Uint8Array))
        throw new TypeError('Expected Uint8Array');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new TypeError(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
}
_assert.bytes = bytes;
function hash(hash) {
    if (typeof hash !== 'function' || typeof hash.create !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    number(hash.outputLen);
    number(hash.blockLen);
}
_assert.hash = hash;
function exists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
_assert.exists = exists;
function output(out, instance) {
    bytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}
_assert.output = output;
const assert = {
    number,
    bool,
    bytes,
    hash,
    exists,
    output,
};
_assert.default = assert;

var utils = {};

var crypto = {};

Object.defineProperty(crypto, "__esModule", { value: true });
crypto.crypto = void 0;
crypto.crypto = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;

(function (exports) {
	/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.randomBytes = exports.wrapConstructorWithOpts = exports.wrapConstructor = exports.checkOpts = exports.Hash = exports.concatBytes = exports.toBytes = exports.utf8ToBytes = exports.asyncLoop = exports.nextTick = exports.hexToBytes = exports.bytesToHex = exports.isLE = exports.rotr = exports.createView = exports.u32 = exports.u8 = void 0;
	// We use `globalThis.crypto`, but node.js versions earlier than v19 don't
	// declare it in global scope. For node.js, package.json#exports field mapping
	// rewrites import from `crypto` to `cryptoNode`, which imports native module.
	// Makes the utils un-importable in browsers without a bundler.
	// Once node.js 18 is deprecated, we can just drop the import.
	const crypto_1 = crypto;
	// Cast array to different type
	const u8 = (arr) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
	exports.u8 = u8;
	const u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
	exports.u32 = u32;
	// Cast array to view
	const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
	exports.createView = createView;
	// The rotate right (circular right shift) operation for uint32
	const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
	exports.rotr = rotr;
	// big-endian hardware is rare. Just in case someone still decides to run hashes:
	// early-throw an error because we don't support BE yet.
	exports.isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
	if (!exports.isLE)
	    throw new Error('Non little-endian hardware is not supported');
	const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
	/**
	 * @example bytesToHex(Uint8Array.from([0xde, 0xad, 0xbe, 0xef])) // 'deadbeef'
	 */
	function bytesToHex(uint8a) {
	    // pre-caching improves the speed 6x
	    if (!(uint8a instanceof Uint8Array))
	        throw new Error('Uint8Array expected');
	    let hex = '';
	    for (let i = 0; i < uint8a.length; i++) {
	        hex += hexes[uint8a[i]];
	    }
	    return hex;
	}
	exports.bytesToHex = bytesToHex;
	/**
	 * @example hexToBytes('deadbeef') // Uint8Array.from([0xde, 0xad, 0xbe, 0xef])
	 */
	function hexToBytes(hex) {
	    if (typeof hex !== 'string') {
	        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
	    }
	    if (hex.length % 2)
	        throw new Error('hexToBytes: received invalid unpadded hex');
	    const array = new Uint8Array(hex.length / 2);
	    for (let i = 0; i < array.length; i++) {
	        const j = i * 2;
	        const hexByte = hex.slice(j, j + 2);
	        const byte = Number.parseInt(hexByte, 16);
	        if (Number.isNaN(byte) || byte < 0)
	            throw new Error('Invalid byte sequence');
	        array[i] = byte;
	    }
	    return array;
	}
	exports.hexToBytes = hexToBytes;
	// There is no setImmediate in browser and setTimeout is slow.
	// call of async fn will return Promise, which will be fullfiled only on
	// next scheduler queue processing step and this is exactly what we need.
	const nextTick = async () => { };
	exports.nextTick = nextTick;
	// Returns control to thread each 'tick' ms to avoid blocking
	async function asyncLoop(iters, tick, cb) {
	    let ts = Date.now();
	    for (let i = 0; i < iters; i++) {
	        cb(i);
	        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
	        const diff = Date.now() - ts;
	        if (diff >= 0 && diff < tick)
	            continue;
	        await (0, exports.nextTick)();
	        ts += diff;
	    }
	}
	exports.asyncLoop = asyncLoop;
	function utf8ToBytes(str) {
	    if (typeof str !== 'string') {
	        throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
	    }
	    return new TextEncoder().encode(str);
	}
	exports.utf8ToBytes = utf8ToBytes;
	function toBytes(data) {
	    if (typeof data === 'string')
	        data = utf8ToBytes(data);
	    if (!(data instanceof Uint8Array))
	        throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
	    return data;
	}
	exports.toBytes = toBytes;
	/**
	 * Concats Uint8Array-s into one; like `Buffer.concat([buf1, buf2])`
	 * @example concatBytes(buf1, buf2)
	 */
	function concatBytes(...arrays) {
	    if (!arrays.every((a) => a instanceof Uint8Array))
	        throw new Error('Uint8Array list expected');
	    if (arrays.length === 1)
	        return arrays[0];
	    const length = arrays.reduce((a, arr) => a + arr.length, 0);
	    const result = new Uint8Array(length);
	    for (let i = 0, pad = 0; i < arrays.length; i++) {
	        const arr = arrays[i];
	        result.set(arr, pad);
	        pad += arr.length;
	    }
	    return result;
	}
	exports.concatBytes = concatBytes;
	// For runtime check if class implements interface
	class Hash {
	    // Safe version that clones internal state
	    clone() {
	        return this._cloneInto();
	    }
	}
	exports.Hash = Hash;
	// Check if object doens't have custom constructor (like Uint8Array/Array)
	const isPlainObject = (obj) => Object.prototype.toString.call(obj) === '[object Object]' && obj.constructor === Object;
	function checkOpts(defaults, opts) {
	    if (opts !== undefined && (typeof opts !== 'object' || !isPlainObject(opts)))
	        throw new TypeError('Options should be object or undefined');
	    const merged = Object.assign(defaults, opts);
	    return merged;
	}
	exports.checkOpts = checkOpts;
	function wrapConstructor(hashConstructor) {
	    const hashC = (message) => hashConstructor().update(toBytes(message)).digest();
	    const tmp = hashConstructor();
	    hashC.outputLen = tmp.outputLen;
	    hashC.blockLen = tmp.blockLen;
	    hashC.create = () => hashConstructor();
	    return hashC;
	}
	exports.wrapConstructor = wrapConstructor;
	function wrapConstructorWithOpts(hashCons) {
	    const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
	    const tmp = hashCons({});
	    hashC.outputLen = tmp.outputLen;
	    hashC.blockLen = tmp.blockLen;
	    hashC.create = (opts) => hashCons(opts);
	    return hashC;
	}
	exports.wrapConstructorWithOpts = wrapConstructorWithOpts;
	/**
	 * Secure PRNG. Uses `globalThis.crypto` or node.js crypto module.
	 */
	function randomBytes(bytesLength = 32) {
	    if (crypto_1.crypto && typeof crypto_1.crypto.getRandomValues === 'function') {
	        return crypto_1.crypto.getRandomValues(new Uint8Array(bytesLength));
	    }
	    throw new Error('crypto.getRandomValues must be defined');
	}
	exports.randomBytes = randomBytes;
	
} (utils));

Object.defineProperty(_sha2, "__esModule", { value: true });
_sha2.SHA2 = void 0;
const _assert_js_1 = _assert;
const utils_js_1$2 = utils;
// Polyfill for Safari 14
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
// Base SHA2 class (RFC 6234)
class SHA2 extends utils_js_1$2.Hash {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.buffer = new Uint8Array(blockLen);
        this.view = (0, utils_js_1$2.createView)(this.buffer);
    }
    update(data) {
        _assert_js_1.default.exists(this);
        const { view, buffer, blockLen } = this;
        data = (0, utils_js_1$2.toBytes)(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = (0, utils_js_1$2.createView)(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        _assert_js_1.default.exists(this);
        _assert_js_1.default.output(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        this.buffer.subarray(pos).fill(0);
        // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = (0, utils_js_1$2.createView)(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen should be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.length = length;
        to.pos = pos;
        to.finished = finished;
        to.destroyed = destroyed;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
}
_sha2.SHA2 = SHA2;

Object.defineProperty(sha256, "__esModule", { value: true });
sha256.sha224 = sha256.sha256 = void 0;
const _sha2_js_1$1 = _sha2;
const utils_js_1$1 = utils;
// Choice: a ? b : c
const Chi = (a, b, c) => (a & b) ^ (~a & c);
// Majority function, true if any two inpust is true
const Maj = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
// Round constants:
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
// prettier-ignore
const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// prettier-ignore
const IV = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA256_W = new Uint32Array(64);
class SHA256 extends _sha2_js_1$1.SHA2 {
    constructor() {
        super(64, 32, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = IV[0] | 0;
        this.B = IV[1] | 0;
        this.C = IV[2] | 0;
        this.D = IV[3] | 0;
        this.E = IV[4] | 0;
        this.F = IV[5] | 0;
        this.G = IV[6] | 0;
        this.H = IV[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = (0, utils_js_1$1.rotr)(W15, 7) ^ (0, utils_js_1$1.rotr)(W15, 18) ^ (W15 >>> 3);
            const s1 = (0, utils_js_1$1.rotr)(W2, 17) ^ (0, utils_js_1$1.rotr)(W2, 19) ^ (W2 >>> 10);
            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = (0, utils_js_1$1.rotr)(E, 6) ^ (0, utils_js_1$1.rotr)(E, 11) ^ (0, utils_js_1$1.rotr)(E, 25);
            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const sigma0 = (0, utils_js_1$1.rotr)(A, 2) ^ (0, utils_js_1$1.rotr)(A, 13) ^ (0, utils_js_1$1.rotr)(A, 22);
            const T2 = (sigma0 + Maj(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        SHA256_W.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
}
// Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
class SHA224 extends SHA256 {
    constructor() {
        super();
        this.A = 0xc1059ed8 | 0;
        this.B = 0x367cd507 | 0;
        this.C = 0x3070dd17 | 0;
        this.D = 0xf70e5939 | 0;
        this.E = 0xffc00b31 | 0;
        this.F = 0x68581511 | 0;
        this.G = 0x64f98fa7 | 0;
        this.H = 0xbefa4fa4 | 0;
        this.outputLen = 28;
    }
}
/**
 * SHA2-256 hash function
 * @param message - data that would be hashed
 */
sha256.sha256 = (0, utils_js_1$1.wrapConstructor)(() => new SHA256());
sha256.sha224 = (0, utils_js_1$1.wrapConstructor)(() => new SHA224());

// base-x encoding / decoding
// Copyright (c) 2018 base-x contributors
// Copyright (c) 2014-2018 The Bitcoin Core developers (base58.cpp)
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
function base (ALPHABET) {
  if (ALPHABET.length >= 255) { throw new TypeError('Alphabet too long') }
  var BASE_MAP = new Uint8Array(256);
  for (var j = 0; j < BASE_MAP.length; j++) {
    BASE_MAP[j] = 255;
  }
  for (var i = 0; i < ALPHABET.length; i++) {
    var x = ALPHABET.charAt(i);
    var xc = x.charCodeAt(0);
    if (BASE_MAP[xc] !== 255) { throw new TypeError(x + ' is ambiguous') }
    BASE_MAP[xc] = i;
  }
  var BASE = ALPHABET.length;
  var LEADER = ALPHABET.charAt(0);
  var FACTOR = Math.log(BASE) / Math.log(256); // log(BASE) / log(256), rounded up
  var iFACTOR = Math.log(256) / Math.log(BASE); // log(256) / log(BASE), rounded up
  function encode (source) {
    if (source instanceof Uint8Array) ; else if (ArrayBuffer.isView(source)) {
      source = new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    } else if (Array.isArray(source)) {
      source = Uint8Array.from(source);
    }
    if (!(source instanceof Uint8Array)) { throw new TypeError('Expected Uint8Array') }
    if (source.length === 0) { return '' }
        // Skip & count leading zeroes.
    var zeroes = 0;
    var length = 0;
    var pbegin = 0;
    var pend = source.length;
    while (pbegin !== pend && source[pbegin] === 0) {
      pbegin++;
      zeroes++;
    }
        // Allocate enough space in big-endian base58 representation.
    var size = ((pend - pbegin) * iFACTOR + 1) >>> 0;
    var b58 = new Uint8Array(size);
        // Process the bytes.
    while (pbegin !== pend) {
      var carry = source[pbegin];
            // Apply "b58 = b58 * 256 + ch".
      var i = 0;
      for (var it1 = size - 1; (carry !== 0 || i < length) && (it1 !== -1); it1--, i++) {
        carry += (256 * b58[it1]) >>> 0;
        b58[it1] = (carry % BASE) >>> 0;
        carry = (carry / BASE) >>> 0;
      }
      if (carry !== 0) { throw new Error('Non-zero carry') }
      length = i;
      pbegin++;
    }
        // Skip leading zeroes in base58 result.
    var it2 = size - length;
    while (it2 !== size && b58[it2] === 0) {
      it2++;
    }
        // Translate the result into a string.
    var str = LEADER.repeat(zeroes);
    for (; it2 < size; ++it2) { str += ALPHABET.charAt(b58[it2]); }
    return str
  }
  function decodeUnsafe (source) {
    if (typeof source !== 'string') { throw new TypeError('Expected String') }
    if (source.length === 0) { return new Uint8Array() }
    var psz = 0;
        // Skip and count leading '1's.
    var zeroes = 0;
    var length = 0;
    while (source[psz] === LEADER) {
      zeroes++;
      psz++;
    }
        // Allocate enough space in big-endian base256 representation.
    var size = (((source.length - psz) * FACTOR) + 1) >>> 0; // log(58) / log(256), rounded up.
    var b256 = new Uint8Array(size);
        // Process the characters.
    while (source[psz]) {
            // Decode character
      var carry = BASE_MAP[source.charCodeAt(psz)];
            // Invalid character
      if (carry === 255) { return }
      var i = 0;
      for (var it3 = size - 1; (carry !== 0 || i < length) && (it3 !== -1); it3--, i++) {
        carry += (BASE * b256[it3]) >>> 0;
        b256[it3] = (carry % 256) >>> 0;
        carry = (carry / 256) >>> 0;
      }
      if (carry !== 0) { throw new Error('Non-zero carry') }
      length = i;
      psz++;
    }
        // Skip leading zeroes in b256.
    var it4 = size - length;
    while (it4 !== size && b256[it4] === 0) {
      it4++;
    }
    var vch = new Uint8Array(zeroes + (size - it4));
    var j = zeroes;
    while (it4 !== size) {
      vch[j++] = b256[it4++];
    }
    return vch
  }
  function decode (string) {
    var buffer = decodeUnsafe(string);
    if (buffer) { return buffer }
    throw new Error('Non-base' + BASE + ' character')
  }
  return {
    encode: encode,
    decodeUnsafe: decodeUnsafe,
    decode: decode
  }
}
var src = base;

(function (exports) {
	var __createBinding = (commonjsGlobal && commonjsGlobal.__createBinding) || (Object.create ? (function(o, m, k, k2) {
	    if (k2 === undefined) k2 = k;
	    var desc = Object.getOwnPropertyDescriptor(m, k);
	    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
	      desc = { enumerable: true, get: function() { return m[k]; } };
	    }
	    Object.defineProperty(o, k2, desc);
	}) : (function(o, m, k, k2) {
	    if (k2 === undefined) k2 = k;
	    o[k2] = m[k];
	}));
	var __setModuleDefault = (commonjsGlobal && commonjsGlobal.__setModuleDefault) || (Object.create ? (function(o, v) {
	    Object.defineProperty(o, "default", { enumerable: true, value: v });
	}) : function(o, v) {
	    o["default"] = v;
	});
	var __importStar = (commonjsGlobal && commonjsGlobal.__importStar) || function (mod) {
	    if (mod && mod.__esModule) return mod;
	    var result = {};
	    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
	    __setModuleDefault(result, mod);
	    return result;
	};
	var __importDefault = (commonjsGlobal && commonjsGlobal.__importDefault) || function (mod) {
	    return (mod && mod.__esModule) ? mod : { "default": mod };
	};
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.Transaction = exports.NULL_ADDRESS = exports.TransactionType = exports.base58 = void 0;
	const ed = __importStar(lib);
	const sha256_1 = sha256;
	const base_x_1 = __importDefault(src);
	exports.base58 = (0, base_x_1.default)('123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ');
	var TransactionType;
	(function (TransactionType) {
	    TransactionType[TransactionType["PAYMENT"] = 0] = "PAYMENT";
	    TransactionType[TransactionType["MINER_FEE"] = 1] = "MINER_FEE";
	    TransactionType[TransactionType["VALIDATOR_FEE"] = 2] = "VALIDATOR_FEE";
	    TransactionType[TransactionType["DEV_FEE"] = 3] = "DEV_FEE";
	    TransactionType[TransactionType["CONTRACT"] = 4] = "CONTRACT";
	})(TransactionType = exports.TransactionType || (exports.TransactionType = {}));
	exports.NULL_ADDRESS = 'kryo:11111111111111111111111111';
	class Transaction {
	    constructor() {
	        this.TransactionType = 0;
	        this.To = exports.NULL_ADDRESS;
	        this.Value = 0;
	        this.MaxFee = 0;
	        this.Nonce = 0;
	    }
	    async Sign(privateKey) {
	        const pk = ed.utils.bytesToHex(decode(privateKey));
	        const buf = new Array();
	        buf.push(...toUint8(Uint16Array.from([this.TransactionType])));
	        buf.push(...decode(this.PublicKey));
	        buf.push(...decode(this.To.replace('kryo:', '')));
	        buf.push(...toUint8(BigUint64Array.from([BigInt(this.Value)])));
	        buf.push(...toUint8(BigUint64Array.from([BigInt(this.MaxFee)])));
	        if (this.Data) {
	            buf.push(...this.Data);
	        }
	        buf.push(...toUint8(Uint32Array.from([this.Nonce])));
	        const message = ed.utils.bytesToHex(Uint8Array.from(buf));
	        this.Signature = encode(await ed.sign(message, pk));
	    }
	    async Verify() {
	        if (!this.Signature || !this.PublicKey) {
	            return false;
	        }
	        const buf = new Array();
	        buf.push(...toUint8(Uint16Array.from([this.TransactionType])));
	        buf.push(...decode(this.PublicKey));
	        buf.push(...decode(this.To.replace('kryo:', '')));
	        buf.push(...toUint8(BigUint64Array.from([BigInt(this.Value)])));
	        buf.push(...toUint8(BigUint64Array.from([BigInt(this.MaxFee)])));
	        if (this.Data) {
	            buf.push(...this.Data);
	        }
	        buf.push(...toUint8(Uint32Array.from([this.Nonce])));
	        const message = ed.utils.bytesToHex(Uint8Array.from(buf));
	        return await ed.verify(decode(this.Signature), message, decode(this.PublicKey));
	    }
	    async CalculateHash() {
	        const buf = new Array();
	        if (this.TransactionType == TransactionType.PAYMENT || this.TransactionType == TransactionType.CONTRACT) {
	            buf.push(...decode(this.PublicKey));
	        }
	        buf.push(...decode(this.To.replace('kryo:', '')));
	        buf.push(...toUint8(BigUint64Array.from([BigInt(this.Value)])));
	        buf.push(...toUint8(BigUint64Array.from([BigInt(this.MaxFee)])));
	        if (this.Data) {
	            buf.push(...this.Data);
	        }
	        buf.push(...toUint8(Uint32Array.from([this.Nonce])));
	        if (this.TransactionType == TransactionType.PAYMENT || this.TransactionType == TransactionType.CONTRACT) {
	            buf.push(...decode(this.Signature));
	        }
	        const hash = (0, sha256_1.sha256)(Uint8Array.from(buf));
	        return encode(hash);
	    }
	    ToJsonString() {
	        return JSON.stringify(this);
	    }
	}
	exports.Transaction = Transaction;
	function toUint8(array) {
	    return new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
	}
	function decode(str) {
	    return exports.base58.decode(str);
	}
	function encode(bytes) {
	    return exports.base58.encode(bytes);
	}
} (transaction));

var ripemd160 = {};

Object.defineProperty(ripemd160, "__esModule", { value: true });
ripemd160.ripemd160 = ripemd160.RIPEMD160 = void 0;
const _sha2_js_1 = _sha2;
const utils_js_1 = utils;
// https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
// https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
const Rho = new Uint8Array([7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]);
const Id = Uint8Array.from({ length: 16 }, (_, i) => i);
const Pi = Id.map((i) => (9 * i + 5) % 16);
let idxL = [Id];
let idxR = [Pi];
for (let i = 0; i < 4; i++)
    for (let j of [idxL, idxR])
        j.push(j[i].map((k) => Rho[k]));
const shifts = [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
    [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
    [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
    [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5],
].map((i) => new Uint8Array(i));
const shiftsL = idxL.map((idx, i) => idx.map((j) => shifts[i][j]));
const shiftsR = idxR.map((idx, i) => idx.map((j) => shifts[i][j]));
const Kl = new Uint32Array([0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]);
const Kr = new Uint32Array([0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000]);
// The rotate left (circular left shift) operation for uint32
const rotl = (word, shift) => (word << shift) | (word >>> (32 - shift));
// It's called f() in spec.
function f(group, x, y, z) {
    if (group === 0)
        return x ^ y ^ z;
    else if (group === 1)
        return (x & y) | (~x & z);
    else if (group === 2)
        return (x | ~y) ^ z;
    else if (group === 3)
        return (x & z) | (y & ~z);
    else
        return x ^ (y | ~z);
}
// Temporary buffer, not used to store anything between runs
const BUF = new Uint32Array(16);
class RIPEMD160 extends _sha2_js_1.SHA2 {
    constructor() {
        super(64, 20, 8, true);
        this.h0 = 0x67452301 | 0;
        this.h1 = 0xefcdab89 | 0;
        this.h2 = 0x98badcfe | 0;
        this.h3 = 0x10325476 | 0;
        this.h4 = 0xc3d2e1f0 | 0;
    }
    get() {
        const { h0, h1, h2, h3, h4 } = this;
        return [h0, h1, h2, h3, h4];
    }
    set(h0, h1, h2, h3, h4) {
        this.h0 = h0 | 0;
        this.h1 = h1 | 0;
        this.h2 = h2 | 0;
        this.h3 = h3 | 0;
        this.h4 = h4 | 0;
    }
    process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
            BUF[i] = view.getUint32(offset, true);
        // prettier-ignore
        let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
        // Instead of iterating 0 to 80, we split it into 5 groups
        // And use the groups in constants, functions, etc. Much simpler
        for (let group = 0; group < 5; group++) {
            const rGroup = 4 - group;
            const hbl = Kl[group], hbr = Kr[group]; // prettier-ignore
            const rl = idxL[group], rr = idxR[group]; // prettier-ignore
            const sl = shiftsL[group], sr = shiftsR[group]; // prettier-ignore
            for (let i = 0; i < 16; i++) {
                const tl = (rotl(al + f(group, bl, cl, dl) + BUF[rl[i]] + hbl, sl[i]) + el) | 0;
                al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl; // prettier-ignore
            }
            // 2 loops are 10% faster
            for (let i = 0; i < 16; i++) {
                const tr = (rotl(ar + f(rGroup, br, cr, dr) + BUF[rr[i]] + hbr, sr[i]) + er) | 0;
                ar = er, er = dr, dr = rotl(cr, 10) | 0, cr = br, br = tr; // prettier-ignore
            }
        }
        // Add the compressed chunk to the current hash value
        this.set((this.h1 + cl + dr) | 0, (this.h2 + dl + er) | 0, (this.h3 + el + ar) | 0, (this.h4 + al + br) | 0, (this.h0 + bl + cr) | 0);
    }
    roundClean() {
        BUF.fill(0);
    }
    destroy() {
        this.destroyed = true;
        this.buffer.fill(0);
        this.set(0, 0, 0, 0, 0);
    }
}
ripemd160.RIPEMD160 = RIPEMD160;
/**
 * RIPEMD-160 - a hash function from 1990s.
 * @param message - msg that would be hashed
 */
ripemd160.ripemd160 = (0, utils_js_1.wrapConstructor)(() => new RIPEMD160());

var __createBinding = (commonjsGlobal && commonjsGlobal.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (commonjsGlobal && commonjsGlobal.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (commonjsGlobal && commonjsGlobal.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(address, "__esModule", { value: true });
address.Address = void 0;
const ed = __importStar(lib);
const transaction_1 = transaction;
const sha256_1 = sha256;
const ripemd160_1 = ripemd160;
const NETWORK = 0xA1;
const WALLET_TYPE = 0;
class Address {
    static async Create() {
        const address = new Address();
        const privKey = ed.utils.randomPrivateKey();
        const pubKey = await ed.getPublicKey(privKey);
        address.PrivateKey = transaction_1.base58.encode(privKey);
        address.PublicKey = transaction_1.base58.encode(pubKey);
        address.Address = toAddress(pubKey);
        return address;
    }
    static async Import(privKeyStr) {
        const address = new Address();
        const pubKey = await ed.getPublicKey(transaction_1.base58.decode(privKeyStr));
        address.PrivateKey = privKeyStr;
        address.PublicKey = transaction_1.base58.encode(pubKey);
        address.Address = toAddress(pubKey);
        return address;
    }
}
address.Address = Address;
function toAddress(pubKey) {
    const encoder = new TextEncoder();
    const shaHash = (0, sha256_1.sha256)(pubKey);
    const ripemdHash = (0, ripemd160_1.ripemd160)(shaHash);
    const addr = Uint8Array.from([NETWORK, WALLET_TYPE, ...ripemdHash]);
    const ripemdBytes = Uint8Array.from([...encoder.encode("kryo:"), ...addr]);
    const stage1 = (0, sha256_1.sha256)(ripemdBytes);
    const stage2 = (0, sha256_1.sha256)(stage1);
    const final = [...addr, ...stage2.slice(0, 4)];
    const bytes = Uint8Array.from(final);
    return 'kryo:' + transaction_1.base58.encode(bytes);
}

(function (exports) {
	var __createBinding = (commonjsGlobal && commonjsGlobal.__createBinding) || (Object.create ? (function(o, m, k, k2) {
	    if (k2 === undefined) k2 = k;
	    var desc = Object.getOwnPropertyDescriptor(m, k);
	    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
	      desc = { enumerable: true, get: function() { return m[k]; } };
	    }
	    Object.defineProperty(o, k2, desc);
	}) : (function(o, m, k, k2) {
	    if (k2 === undefined) k2 = k;
	    o[k2] = m[k];
	}));
	var __exportStar = (commonjsGlobal && commonjsGlobal.__exportStar) || function(m, exports) {
	    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
	};
	Object.defineProperty(exports, "__esModule", { value: true });
	__exportStar(address, exports);
	__exportStar(transaction, exports);
} (build));

var index = /*@__PURE__*/getDefaultExportFromCjs(build);

export { index as default };
