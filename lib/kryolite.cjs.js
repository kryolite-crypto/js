'use strict';

var require$$0 = require('crypto');

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

var cryptoJsExports = {};
var cryptoJs = {
  get exports(){ return cryptoJsExports; },
  set exports(v){ cryptoJsExports = v; },
};

function commonjsRequire(path) {
	throw new Error('Could not dynamically require "' + path + '". Please configure the dynamicRequireTargets or/and ignoreDynamicRequires option of @rollup/plugin-commonjs appropriately for this require call to work.');
}

var coreExports = {};
var core = {
  get exports(){ return coreExports; },
  set exports(v){ coreExports = v; },
};

var hasRequiredCore;

function requireCore () {
	if (hasRequiredCore) return coreExports;
	hasRequiredCore = 1;
	(function (module, exports) {
(function (root, factory) {
			{
				// CommonJS
				module.exports = factory();
			}
		}(commonjsGlobal, function () {

			/*globals window, global, require*/

			/**
			 * CryptoJS core components.
			 */
			var CryptoJS = CryptoJS || (function (Math, undefined$1) {

			    var crypto;

			    // Native crypto from window (Browser)
			    if (typeof window !== 'undefined' && window.crypto) {
			        crypto = window.crypto;
			    }

			    // Native crypto in web worker (Browser)
			    if (typeof self !== 'undefined' && self.crypto) {
			        crypto = self.crypto;
			    }

			    // Native crypto from worker
			    if (typeof globalThis !== 'undefined' && globalThis.crypto) {
			        crypto = globalThis.crypto;
			    }

			    // Native (experimental IE 11) crypto from window (Browser)
			    if (!crypto && typeof window !== 'undefined' && window.msCrypto) {
			        crypto = window.msCrypto;
			    }

			    // Native crypto from global (NodeJS)
			    if (!crypto && typeof commonjsGlobal !== 'undefined' && commonjsGlobal.crypto) {
			        crypto = commonjsGlobal.crypto;
			    }

			    // Native crypto import via require (NodeJS)
			    if (!crypto && typeof commonjsRequire === 'function') {
			        try {
			            crypto = require('crypto');
			        } catch (err) {}
			    }

			    /*
			     * Cryptographically secure pseudorandom number generator
			     *
			     * As Math.random() is cryptographically not safe to use
			     */
			    var cryptoSecureRandomInt = function () {
			        if (crypto) {
			            // Use getRandomValues method (Browser)
			            if (typeof crypto.getRandomValues === 'function') {
			                try {
			                    return crypto.getRandomValues(new Uint32Array(1))[0];
			                } catch (err) {}
			            }

			            // Use randomBytes method (NodeJS)
			            if (typeof crypto.randomBytes === 'function') {
			                try {
			                    return crypto.randomBytes(4).readInt32LE();
			                } catch (err) {}
			            }
			        }

			        throw new Error('Native crypto module could not be used to get secure random number.');
			    };

			    /*
			     * Local polyfill of Object.create

			     */
			    var create = Object.create || (function () {
			        function F() {}

			        return function (obj) {
			            var subtype;

			            F.prototype = obj;

			            subtype = new F();

			            F.prototype = null;

			            return subtype;
			        };
			    }());

			    /**
			     * CryptoJS namespace.
			     */
			    var C = {};

			    /**
			     * Library namespace.
			     */
			    var C_lib = C.lib = {};

			    /**
			     * Base object for prototypal inheritance.
			     */
			    var Base = C_lib.Base = (function () {


			        return {
			            /**
			             * Creates a new object that inherits from this object.
			             *
			             * @param {Object} overrides Properties to copy into the new object.
			             *
			             * @return {Object} The new object.
			             *
			             * @static
			             *
			             * @example
			             *
			             *     var MyType = CryptoJS.lib.Base.extend({
			             *         field: 'value',
			             *
			             *         method: function () {
			             *         }
			             *     });
			             */
			            extend: function (overrides) {
			                // Spawn
			                var subtype = create(this);

			                // Augment
			                if (overrides) {
			                    subtype.mixIn(overrides);
			                }

			                // Create default initializer
			                if (!subtype.hasOwnProperty('init') || this.init === subtype.init) {
			                    subtype.init = function () {
			                        subtype.$super.init.apply(this, arguments);
			                    };
			                }

			                // Initializer's prototype is the subtype object
			                subtype.init.prototype = subtype;

			                // Reference supertype
			                subtype.$super = this;

			                return subtype;
			            },

			            /**
			             * Extends this object and runs the init method.
			             * Arguments to create() will be passed to init().
			             *
			             * @return {Object} The new object.
			             *
			             * @static
			             *
			             * @example
			             *
			             *     var instance = MyType.create();
			             */
			            create: function () {
			                var instance = this.extend();
			                instance.init.apply(instance, arguments);

			                return instance;
			            },

			            /**
			             * Initializes a newly created object.
			             * Override this method to add some logic when your objects are created.
			             *
			             * @example
			             *
			             *     var MyType = CryptoJS.lib.Base.extend({
			             *         init: function () {
			             *             // ...
			             *         }
			             *     });
			             */
			            init: function () {
			            },

			            /**
			             * Copies properties into this object.
			             *
			             * @param {Object} properties The properties to mix in.
			             *
			             * @example
			             *
			             *     MyType.mixIn({
			             *         field: 'value'
			             *     });
			             */
			            mixIn: function (properties) {
			                for (var propertyName in properties) {
			                    if (properties.hasOwnProperty(propertyName)) {
			                        this[propertyName] = properties[propertyName];
			                    }
			                }

			                // IE won't copy toString using the loop above
			                if (properties.hasOwnProperty('toString')) {
			                    this.toString = properties.toString;
			                }
			            },

			            /**
			             * Creates a copy of this object.
			             *
			             * @return {Object} The clone.
			             *
			             * @example
			             *
			             *     var clone = instance.clone();
			             */
			            clone: function () {
			                return this.init.prototype.extend(this);
			            }
			        };
			    }());

			    /**
			     * An array of 32-bit words.
			     *
			     * @property {Array} words The array of 32-bit words.
			     * @property {number} sigBytes The number of significant bytes in this word array.
			     */
			    var WordArray = C_lib.WordArray = Base.extend({
			        /**
			         * Initializes a newly created word array.
			         *
			         * @param {Array} words (Optional) An array of 32-bit words.
			         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
			         *
			         * @example
			         *
			         *     var wordArray = CryptoJS.lib.WordArray.create();
			         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
			         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
			         */
			        init: function (words, sigBytes) {
			            words = this.words = words || [];

			            if (sigBytes != undefined$1) {
			                this.sigBytes = sigBytes;
			            } else {
			                this.sigBytes = words.length * 4;
			            }
			        },

			        /**
			         * Converts this word array to a string.
			         *
			         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
			         *
			         * @return {string} The stringified word array.
			         *
			         * @example
			         *
			         *     var string = wordArray + '';
			         *     var string = wordArray.toString();
			         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
			         */
			        toString: function (encoder) {
			            return (encoder || Hex).stringify(this);
			        },

			        /**
			         * Concatenates a word array to this word array.
			         *
			         * @param {WordArray} wordArray The word array to append.
			         *
			         * @return {WordArray} This word array.
			         *
			         * @example
			         *
			         *     wordArray1.concat(wordArray2);
			         */
			        concat: function (wordArray) {
			            // Shortcuts
			            var thisWords = this.words;
			            var thatWords = wordArray.words;
			            var thisSigBytes = this.sigBytes;
			            var thatSigBytes = wordArray.sigBytes;

			            // Clamp excess bits
			            this.clamp();

			            // Concat
			            if (thisSigBytes % 4) {
			                // Copy one byte at a time
			                for (var i = 0; i < thatSigBytes; i++) {
			                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
			                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
			                }
			            } else {
			                // Copy one word at a time
			                for (var j = 0; j < thatSigBytes; j += 4) {
			                    thisWords[(thisSigBytes + j) >>> 2] = thatWords[j >>> 2];
			                }
			            }
			            this.sigBytes += thatSigBytes;

			            // Chainable
			            return this;
			        },

			        /**
			         * Removes insignificant bits.
			         *
			         * @example
			         *
			         *     wordArray.clamp();
			         */
			        clamp: function () {
			            // Shortcuts
			            var words = this.words;
			            var sigBytes = this.sigBytes;

			            // Clamp
			            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
			            words.length = Math.ceil(sigBytes / 4);
			        },

			        /**
			         * Creates a copy of this word array.
			         *
			         * @return {WordArray} The clone.
			         *
			         * @example
			         *
			         *     var clone = wordArray.clone();
			         */
			        clone: function () {
			            var clone = Base.clone.call(this);
			            clone.words = this.words.slice(0);

			            return clone;
			        },

			        /**
			         * Creates a word array filled with random bytes.
			         *
			         * @param {number} nBytes The number of random bytes to generate.
			         *
			         * @return {WordArray} The random word array.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var wordArray = CryptoJS.lib.WordArray.random(16);
			         */
			        random: function (nBytes) {
			            var words = [];

			            for (var i = 0; i < nBytes; i += 4) {
			                words.push(cryptoSecureRandomInt());
			            }

			            return new WordArray.init(words, nBytes);
			        }
			    });

			    /**
			     * Encoder namespace.
			     */
			    var C_enc = C.enc = {};

			    /**
			     * Hex encoding strategy.
			     */
			    var Hex = C_enc.Hex = {
			        /**
			         * Converts a word array to a hex string.
			         *
			         * @param {WordArray} wordArray The word array.
			         *
			         * @return {string} The hex string.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
			         */
			        stringify: function (wordArray) {
			            // Shortcuts
			            var words = wordArray.words;
			            var sigBytes = wordArray.sigBytes;

			            // Convert
			            var hexChars = [];
			            for (var i = 0; i < sigBytes; i++) {
			                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
			                hexChars.push((bite >>> 4).toString(16));
			                hexChars.push((bite & 0x0f).toString(16));
			            }

			            return hexChars.join('');
			        },

			        /**
			         * Converts a hex string to a word array.
			         *
			         * @param {string} hexStr The hex string.
			         *
			         * @return {WordArray} The word array.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
			         */
			        parse: function (hexStr) {
			            // Shortcut
			            var hexStrLength = hexStr.length;

			            // Convert
			            var words = [];
			            for (var i = 0; i < hexStrLength; i += 2) {
			                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
			            }

			            return new WordArray.init(words, hexStrLength / 2);
			        }
			    };

			    /**
			     * Latin1 encoding strategy.
			     */
			    var Latin1 = C_enc.Latin1 = {
			        /**
			         * Converts a word array to a Latin1 string.
			         *
			         * @param {WordArray} wordArray The word array.
			         *
			         * @return {string} The Latin1 string.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
			         */
			        stringify: function (wordArray) {
			            // Shortcuts
			            var words = wordArray.words;
			            var sigBytes = wordArray.sigBytes;

			            // Convert
			            var latin1Chars = [];
			            for (var i = 0; i < sigBytes; i++) {
			                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
			                latin1Chars.push(String.fromCharCode(bite));
			            }

			            return latin1Chars.join('');
			        },

			        /**
			         * Converts a Latin1 string to a word array.
			         *
			         * @param {string} latin1Str The Latin1 string.
			         *
			         * @return {WordArray} The word array.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
			         */
			        parse: function (latin1Str) {
			            // Shortcut
			            var latin1StrLength = latin1Str.length;

			            // Convert
			            var words = [];
			            for (var i = 0; i < latin1StrLength; i++) {
			                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
			            }

			            return new WordArray.init(words, latin1StrLength);
			        }
			    };

			    /**
			     * UTF-8 encoding strategy.
			     */
			    var Utf8 = C_enc.Utf8 = {
			        /**
			         * Converts a word array to a UTF-8 string.
			         *
			         * @param {WordArray} wordArray The word array.
			         *
			         * @return {string} The UTF-8 string.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
			         */
			        stringify: function (wordArray) {
			            try {
			                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
			            } catch (e) {
			                throw new Error('Malformed UTF-8 data');
			            }
			        },

			        /**
			         * Converts a UTF-8 string to a word array.
			         *
			         * @param {string} utf8Str The UTF-8 string.
			         *
			         * @return {WordArray} The word array.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
			         */
			        parse: function (utf8Str) {
			            return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
			        }
			    };

			    /**
			     * Abstract buffered block algorithm template.
			     *
			     * The property blockSize must be implemented in a concrete subtype.
			     *
			     * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
			     */
			    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
			        /**
			         * Resets this block algorithm's data buffer to its initial state.
			         *
			         * @example
			         *
			         *     bufferedBlockAlgorithm.reset();
			         */
			        reset: function () {
			            // Initial values
			            this._data = new WordArray.init();
			            this._nDataBytes = 0;
			        },

			        /**
			         * Adds new data to this block algorithm's buffer.
			         *
			         * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
			         *
			         * @example
			         *
			         *     bufferedBlockAlgorithm._append('data');
			         *     bufferedBlockAlgorithm._append(wordArray);
			         */
			        _append: function (data) {
			            // Convert string to WordArray, else assume WordArray already
			            if (typeof data == 'string') {
			                data = Utf8.parse(data);
			            }

			            // Append
			            this._data.concat(data);
			            this._nDataBytes += data.sigBytes;
			        },

			        /**
			         * Processes available data blocks.
			         *
			         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
			         *
			         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
			         *
			         * @return {WordArray} The processed data.
			         *
			         * @example
			         *
			         *     var processedData = bufferedBlockAlgorithm._process();
			         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
			         */
			        _process: function (doFlush) {
			            var processedWords;

			            // Shortcuts
			            var data = this._data;
			            var dataWords = data.words;
			            var dataSigBytes = data.sigBytes;
			            var blockSize = this.blockSize;
			            var blockSizeBytes = blockSize * 4;

			            // Count blocks ready
			            var nBlocksReady = dataSigBytes / blockSizeBytes;
			            if (doFlush) {
			                // Round up to include partial blocks
			                nBlocksReady = Math.ceil(nBlocksReady);
			            } else {
			                // Round down to include only full blocks,
			                // less the number of blocks that must remain in the buffer
			                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
			            }

			            // Count words ready
			            var nWordsReady = nBlocksReady * blockSize;

			            // Count bytes ready
			            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

			            // Process blocks
			            if (nWordsReady) {
			                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
			                    // Perform concrete-algorithm logic
			                    this._doProcessBlock(dataWords, offset);
			                }

			                // Remove processed words
			                processedWords = dataWords.splice(0, nWordsReady);
			                data.sigBytes -= nBytesReady;
			            }

			            // Return processed words
			            return new WordArray.init(processedWords, nBytesReady);
			        },

			        /**
			         * Creates a copy of this object.
			         *
			         * @return {Object} The clone.
			         *
			         * @example
			         *
			         *     var clone = bufferedBlockAlgorithm.clone();
			         */
			        clone: function () {
			            var clone = Base.clone.call(this);
			            clone._data = this._data.clone();

			            return clone;
			        },

			        _minBufferSize: 0
			    });

			    /**
			     * Abstract hasher template.
			     *
			     * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
			     */
			    C_lib.Hasher = BufferedBlockAlgorithm.extend({
			        /**
			         * Configuration options.
			         */
			        cfg: Base.extend(),

			        /**
			         * Initializes a newly created hasher.
			         *
			         * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
			         *
			         * @example
			         *
			         *     var hasher = CryptoJS.algo.SHA256.create();
			         */
			        init: function (cfg) {
			            // Apply config defaults
			            this.cfg = this.cfg.extend(cfg);

			            // Set initial values
			            this.reset();
			        },

			        /**
			         * Resets this hasher to its initial state.
			         *
			         * @example
			         *
			         *     hasher.reset();
			         */
			        reset: function () {
			            // Reset data buffer
			            BufferedBlockAlgorithm.reset.call(this);

			            // Perform concrete-hasher logic
			            this._doReset();
			        },

			        /**
			         * Updates this hasher with a message.
			         *
			         * @param {WordArray|string} messageUpdate The message to append.
			         *
			         * @return {Hasher} This hasher.
			         *
			         * @example
			         *
			         *     hasher.update('message');
			         *     hasher.update(wordArray);
			         */
			        update: function (messageUpdate) {
			            // Append
			            this._append(messageUpdate);

			            // Update the hash
			            this._process();

			            // Chainable
			            return this;
			        },

			        /**
			         * Finalizes the hash computation.
			         * Note that the finalize operation is effectively a destructive, read-once operation.
			         *
			         * @param {WordArray|string} messageUpdate (Optional) A final message update.
			         *
			         * @return {WordArray} The hash.
			         *
			         * @example
			         *
			         *     var hash = hasher.finalize();
			         *     var hash = hasher.finalize('message');
			         *     var hash = hasher.finalize(wordArray);
			         */
			        finalize: function (messageUpdate) {
			            // Final message update
			            if (messageUpdate) {
			                this._append(messageUpdate);
			            }

			            // Perform concrete-hasher logic
			            var hash = this._doFinalize();

			            return hash;
			        },

			        blockSize: 512/32,

			        /**
			         * Creates a shortcut function to a hasher's object interface.
			         *
			         * @param {Hasher} hasher The hasher to create a helper for.
			         *
			         * @return {Function} The shortcut function.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
			         */
			        _createHelper: function (hasher) {
			            return function (message, cfg) {
			                return new hasher.init(cfg).finalize(message);
			            };
			        },

			        /**
			         * Creates a shortcut function to the HMAC's object interface.
			         *
			         * @param {Hasher} hasher The hasher to use in this HMAC helper.
			         *
			         * @return {Function} The shortcut function.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
			         */
			        _createHmacHelper: function (hasher) {
			            return function (message, key) {
			                return new C_algo.HMAC.init(hasher, key).finalize(message);
			            };
			        }
			    });

			    /**
			     * Algorithm namespace.
			     */
			    var C_algo = C.algo = {};

			    return C;
			}(Math));


			return CryptoJS;

		}));
} (core));
	return coreExports;
}

var x64CoreExports = {};
var x64Core = {
  get exports(){ return x64CoreExports; },
  set exports(v){ x64CoreExports = v; },
};

var hasRequiredX64Core;

function requireX64Core () {
	if (hasRequiredX64Core) return x64CoreExports;
	hasRequiredX64Core = 1;
	(function (module, exports) {
(function (root, factory) {
			{
				// CommonJS
				module.exports = factory(requireCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function (undefined$1) {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var Base = C_lib.Base;
			    var X32WordArray = C_lib.WordArray;

			    /**
			     * x64 namespace.
			     */
			    var C_x64 = C.x64 = {};

			    /**
			     * A 64-bit word.
			     */
			    C_x64.Word = Base.extend({
			        /**
			         * Initializes a newly created 64-bit word.
			         *
			         * @param {number} high The high 32 bits.
			         * @param {number} low The low 32 bits.
			         *
			         * @example
			         *
			         *     var x64Word = CryptoJS.x64.Word.create(0x00010203, 0x04050607);
			         */
			        init: function (high, low) {
			            this.high = high;
			            this.low = low;
			        }

			        /**
			         * Bitwise NOTs this word.
			         *
			         * @return {X64Word} A new x64-Word object after negating.
			         *
			         * @example
			         *
			         *     var negated = x64Word.not();
			         */
			        // not: function () {
			            // var high = ~this.high;
			            // var low = ~this.low;

			            // return X64Word.create(high, low);
			        // },

			        /**
			         * Bitwise ANDs this word with the passed word.
			         *
			         * @param {X64Word} word The x64-Word to AND with this word.
			         *
			         * @return {X64Word} A new x64-Word object after ANDing.
			         *
			         * @example
			         *
			         *     var anded = x64Word.and(anotherX64Word);
			         */
			        // and: function (word) {
			            // var high = this.high & word.high;
			            // var low = this.low & word.low;

			            // return X64Word.create(high, low);
			        // },

			        /**
			         * Bitwise ORs this word with the passed word.
			         *
			         * @param {X64Word} word The x64-Word to OR with this word.
			         *
			         * @return {X64Word} A new x64-Word object after ORing.
			         *
			         * @example
			         *
			         *     var ored = x64Word.or(anotherX64Word);
			         */
			        // or: function (word) {
			            // var high = this.high | word.high;
			            // var low = this.low | word.low;

			            // return X64Word.create(high, low);
			        // },

			        /**
			         * Bitwise XORs this word with the passed word.
			         *
			         * @param {X64Word} word The x64-Word to XOR with this word.
			         *
			         * @return {X64Word} A new x64-Word object after XORing.
			         *
			         * @example
			         *
			         *     var xored = x64Word.xor(anotherX64Word);
			         */
			        // xor: function (word) {
			            // var high = this.high ^ word.high;
			            // var low = this.low ^ word.low;

			            // return X64Word.create(high, low);
			        // },

			        /**
			         * Shifts this word n bits to the left.
			         *
			         * @param {number} n The number of bits to shift.
			         *
			         * @return {X64Word} A new x64-Word object after shifting.
			         *
			         * @example
			         *
			         *     var shifted = x64Word.shiftL(25);
			         */
			        // shiftL: function (n) {
			            // if (n < 32) {
			                // var high = (this.high << n) | (this.low >>> (32 - n));
			                // var low = this.low << n;
			            // } else {
			                // var high = this.low << (n - 32);
			                // var low = 0;
			            // }

			            // return X64Word.create(high, low);
			        // },

			        /**
			         * Shifts this word n bits to the right.
			         *
			         * @param {number} n The number of bits to shift.
			         *
			         * @return {X64Word} A new x64-Word object after shifting.
			         *
			         * @example
			         *
			         *     var shifted = x64Word.shiftR(7);
			         */
			        // shiftR: function (n) {
			            // if (n < 32) {
			                // var low = (this.low >>> n) | (this.high << (32 - n));
			                // var high = this.high >>> n;
			            // } else {
			                // var low = this.high >>> (n - 32);
			                // var high = 0;
			            // }

			            // return X64Word.create(high, low);
			        // },

			        /**
			         * Rotates this word n bits to the left.
			         *
			         * @param {number} n The number of bits to rotate.
			         *
			         * @return {X64Word} A new x64-Word object after rotating.
			         *
			         * @example
			         *
			         *     var rotated = x64Word.rotL(25);
			         */
			        // rotL: function (n) {
			            // return this.shiftL(n).or(this.shiftR(64 - n));
			        // },

			        /**
			         * Rotates this word n bits to the right.
			         *
			         * @param {number} n The number of bits to rotate.
			         *
			         * @return {X64Word} A new x64-Word object after rotating.
			         *
			         * @example
			         *
			         *     var rotated = x64Word.rotR(7);
			         */
			        // rotR: function (n) {
			            // return this.shiftR(n).or(this.shiftL(64 - n));
			        // },

			        /**
			         * Adds this word with the passed word.
			         *
			         * @param {X64Word} word The x64-Word to add with this word.
			         *
			         * @return {X64Word} A new x64-Word object after adding.
			         *
			         * @example
			         *
			         *     var added = x64Word.add(anotherX64Word);
			         */
			        // add: function (word) {
			            // var low = (this.low + word.low) | 0;
			            // var carry = (low >>> 0) < (this.low >>> 0) ? 1 : 0;
			            // var high = (this.high + word.high + carry) | 0;

			            // return X64Word.create(high, low);
			        // }
			    });

			    /**
			     * An array of 64-bit words.
			     *
			     * @property {Array} words The array of CryptoJS.x64.Word objects.
			     * @property {number} sigBytes The number of significant bytes in this word array.
			     */
			    C_x64.WordArray = Base.extend({
			        /**
			         * Initializes a newly created word array.
			         *
			         * @param {Array} words (Optional) An array of CryptoJS.x64.Word objects.
			         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
			         *
			         * @example
			         *
			         *     var wordArray = CryptoJS.x64.WordArray.create();
			         *
			         *     var wordArray = CryptoJS.x64.WordArray.create([
			         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
			         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
			         *     ]);
			         *
			         *     var wordArray = CryptoJS.x64.WordArray.create([
			         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
			         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
			         *     ], 10);
			         */
			        init: function (words, sigBytes) {
			            words = this.words = words || [];

			            if (sigBytes != undefined$1) {
			                this.sigBytes = sigBytes;
			            } else {
			                this.sigBytes = words.length * 8;
			            }
			        },

			        /**
			         * Converts this 64-bit word array to a 32-bit word array.
			         *
			         * @return {CryptoJS.lib.WordArray} This word array's data as a 32-bit word array.
			         *
			         * @example
			         *
			         *     var x32WordArray = x64WordArray.toX32();
			         */
			        toX32: function () {
			            // Shortcuts
			            var x64Words = this.words;
			            var x64WordsLength = x64Words.length;

			            // Convert
			            var x32Words = [];
			            for (var i = 0; i < x64WordsLength; i++) {
			                var x64Word = x64Words[i];
			                x32Words.push(x64Word.high);
			                x32Words.push(x64Word.low);
			            }

			            return X32WordArray.create(x32Words, this.sigBytes);
			        },

			        /**
			         * Creates a copy of this word array.
			         *
			         * @return {X64WordArray} The clone.
			         *
			         * @example
			         *
			         *     var clone = x64WordArray.clone();
			         */
			        clone: function () {
			            var clone = Base.clone.call(this);

			            // Clone "words" array
			            var words = clone.words = this.words.slice(0);

			            // Clone each X64Word object
			            var wordsLength = words.length;
			            for (var i = 0; i < wordsLength; i++) {
			                words[i] = words[i].clone();
			            }

			            return clone;
			        }
			    });
			}());


			return CryptoJS;

		}));
} (x64Core));
	return x64CoreExports;
}

var libTypedarraysExports = {};
var libTypedarrays = {
  get exports(){ return libTypedarraysExports; },
  set exports(v){ libTypedarraysExports = v; },
};

var hasRequiredLibTypedarrays;

function requireLibTypedarrays () {
	if (hasRequiredLibTypedarrays) return libTypedarraysExports;
	hasRequiredLibTypedarrays = 1;
	(function (module, exports) {
(function (root, factory) {
			{
				// CommonJS
				module.exports = factory(requireCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Check if typed arrays are supported
			    if (typeof ArrayBuffer != 'function') {
			        return;
			    }

			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var WordArray = C_lib.WordArray;

			    // Reference original init
			    var superInit = WordArray.init;

			    // Augment WordArray.init to handle typed arrays
			    var subInit = WordArray.init = function (typedArray) {
			        // Convert buffers to uint8
			        if (typedArray instanceof ArrayBuffer) {
			            typedArray = new Uint8Array(typedArray);
			        }

			        // Convert other array views to uint8
			        if (
			            typedArray instanceof Int8Array ||
			            (typeof Uint8ClampedArray !== "undefined" && typedArray instanceof Uint8ClampedArray) ||
			            typedArray instanceof Int16Array ||
			            typedArray instanceof Uint16Array ||
			            typedArray instanceof Int32Array ||
			            typedArray instanceof Uint32Array ||
			            typedArray instanceof Float32Array ||
			            typedArray instanceof Float64Array
			        ) {
			            typedArray = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
			        }

			        // Handle Uint8Array
			        if (typedArray instanceof Uint8Array) {
			            // Shortcut
			            var typedArrayByteLength = typedArray.byteLength;

			            // Extract bytes
			            var words = [];
			            for (var i = 0; i < typedArrayByteLength; i++) {
			                words[i >>> 2] |= typedArray[i] << (24 - (i % 4) * 8);
			            }

			            // Initialize this word array
			            superInit.call(this, words, typedArrayByteLength);
			        } else {
			            // Else call normal init
			            superInit.apply(this, arguments);
			        }
			    };

			    subInit.prototype = WordArray;
			}());


			return CryptoJS.lib.WordArray;

		}));
} (libTypedarrays));
	return libTypedarraysExports;
}

var encUtf16Exports = {};
var encUtf16 = {
  get exports(){ return encUtf16Exports; },
  set exports(v){ encUtf16Exports = v; },
};

var hasRequiredEncUtf16;

function requireEncUtf16 () {
	if (hasRequiredEncUtf16) return encUtf16Exports;
	hasRequiredEncUtf16 = 1;
	(function (module, exports) {
(function (root, factory) {
			{
				// CommonJS
				module.exports = factory(requireCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var WordArray = C_lib.WordArray;
			    var C_enc = C.enc;

			    /**
			     * UTF-16 BE encoding strategy.
			     */
			    C_enc.Utf16 = C_enc.Utf16BE = {
			        /**
			         * Converts a word array to a UTF-16 BE string.
			         *
			         * @param {WordArray} wordArray The word array.
			         *
			         * @return {string} The UTF-16 BE string.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var utf16String = CryptoJS.enc.Utf16.stringify(wordArray);
			         */
			        stringify: function (wordArray) {
			            // Shortcuts
			            var words = wordArray.words;
			            var sigBytes = wordArray.sigBytes;

			            // Convert
			            var utf16Chars = [];
			            for (var i = 0; i < sigBytes; i += 2) {
			                var codePoint = (words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff;
			                utf16Chars.push(String.fromCharCode(codePoint));
			            }

			            return utf16Chars.join('');
			        },

			        /**
			         * Converts a UTF-16 BE string to a word array.
			         *
			         * @param {string} utf16Str The UTF-16 BE string.
			         *
			         * @return {WordArray} The word array.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var wordArray = CryptoJS.enc.Utf16.parse(utf16String);
			         */
			        parse: function (utf16Str) {
			            // Shortcut
			            var utf16StrLength = utf16Str.length;

			            // Convert
			            var words = [];
			            for (var i = 0; i < utf16StrLength; i++) {
			                words[i >>> 1] |= utf16Str.charCodeAt(i) << (16 - (i % 2) * 16);
			            }

			            return WordArray.create(words, utf16StrLength * 2);
			        }
			    };

			    /**
			     * UTF-16 LE encoding strategy.
			     */
			    C_enc.Utf16LE = {
			        /**
			         * Converts a word array to a UTF-16 LE string.
			         *
			         * @param {WordArray} wordArray The word array.
			         *
			         * @return {string} The UTF-16 LE string.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var utf16Str = CryptoJS.enc.Utf16LE.stringify(wordArray);
			         */
			        stringify: function (wordArray) {
			            // Shortcuts
			            var words = wordArray.words;
			            var sigBytes = wordArray.sigBytes;

			            // Convert
			            var utf16Chars = [];
			            for (var i = 0; i < sigBytes; i += 2) {
			                var codePoint = swapEndian((words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff);
			                utf16Chars.push(String.fromCharCode(codePoint));
			            }

			            return utf16Chars.join('');
			        },

			        /**
			         * Converts a UTF-16 LE string to a word array.
			         *
			         * @param {string} utf16Str The UTF-16 LE string.
			         *
			         * @return {WordArray} The word array.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var wordArray = CryptoJS.enc.Utf16LE.parse(utf16Str);
			         */
			        parse: function (utf16Str) {
			            // Shortcut
			            var utf16StrLength = utf16Str.length;

			            // Convert
			            var words = [];
			            for (var i = 0; i < utf16StrLength; i++) {
			                words[i >>> 1] |= swapEndian(utf16Str.charCodeAt(i) << (16 - (i % 2) * 16));
			            }

			            return WordArray.create(words, utf16StrLength * 2);
			        }
			    };

			    function swapEndian(word) {
			        return ((word << 8) & 0xff00ff00) | ((word >>> 8) & 0x00ff00ff);
			    }
			}());


			return CryptoJS.enc.Utf16;

		}));
} (encUtf16));
	return encUtf16Exports;
}

var encBase64Exports = {};
var encBase64 = {
  get exports(){ return encBase64Exports; },
  set exports(v){ encBase64Exports = v; },
};

var hasRequiredEncBase64;

function requireEncBase64 () {
	if (hasRequiredEncBase64) return encBase64Exports;
	hasRequiredEncBase64 = 1;
	(function (module, exports) {
(function (root, factory) {
			{
				// CommonJS
				module.exports = factory(requireCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var WordArray = C_lib.WordArray;
			    var C_enc = C.enc;

			    /**
			     * Base64 encoding strategy.
			     */
			    C_enc.Base64 = {
			        /**
			         * Converts a word array to a Base64 string.
			         *
			         * @param {WordArray} wordArray The word array.
			         *
			         * @return {string} The Base64 string.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var base64String = CryptoJS.enc.Base64.stringify(wordArray);
			         */
			        stringify: function (wordArray) {
			            // Shortcuts
			            var words = wordArray.words;
			            var sigBytes = wordArray.sigBytes;
			            var map = this._map;

			            // Clamp excess bits
			            wordArray.clamp();

			            // Convert
			            var base64Chars = [];
			            for (var i = 0; i < sigBytes; i += 3) {
			                var byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
			                var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
			                var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

			                var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

			                for (var j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
			                    base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
			                }
			            }

			            // Add padding
			            var paddingChar = map.charAt(64);
			            if (paddingChar) {
			                while (base64Chars.length % 4) {
			                    base64Chars.push(paddingChar);
			                }
			            }

			            return base64Chars.join('');
			        },

			        /**
			         * Converts a Base64 string to a word array.
			         *
			         * @param {string} base64Str The Base64 string.
			         *
			         * @return {WordArray} The word array.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var wordArray = CryptoJS.enc.Base64.parse(base64String);
			         */
			        parse: function (base64Str) {
			            // Shortcuts
			            var base64StrLength = base64Str.length;
			            var map = this._map;
			            var reverseMap = this._reverseMap;

			            if (!reverseMap) {
			                    reverseMap = this._reverseMap = [];
			                    for (var j = 0; j < map.length; j++) {
			                        reverseMap[map.charCodeAt(j)] = j;
			                    }
			            }

			            // Ignore padding
			            var paddingChar = map.charAt(64);
			            if (paddingChar) {
			                var paddingIndex = base64Str.indexOf(paddingChar);
			                if (paddingIndex !== -1) {
			                    base64StrLength = paddingIndex;
			                }
			            }

			            // Convert
			            return parseLoop(base64Str, base64StrLength, reverseMap);

			        },

			        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
			    };

			    function parseLoop(base64Str, base64StrLength, reverseMap) {
			      var words = [];
			      var nBytes = 0;
			      for (var i = 0; i < base64StrLength; i++) {
			          if (i % 4) {
			              var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
			              var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
			              var bitsCombined = bits1 | bits2;
			              words[nBytes >>> 2] |= bitsCombined << (24 - (nBytes % 4) * 8);
			              nBytes++;
			          }
			      }
			      return WordArray.create(words, nBytes);
			    }
			}());


			return CryptoJS.enc.Base64;

		}));
} (encBase64));
	return encBase64Exports;
}

var encBase64urlExports = {};
var encBase64url = {
  get exports(){ return encBase64urlExports; },
  set exports(v){ encBase64urlExports = v; },
};

var hasRequiredEncBase64url;

function requireEncBase64url () {
	if (hasRequiredEncBase64url) return encBase64urlExports;
	hasRequiredEncBase64url = 1;
	(function (module, exports) {
(function (root, factory) {
			{
				// CommonJS
				module.exports = factory(requireCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var WordArray = C_lib.WordArray;
			    var C_enc = C.enc;

			    /**
			     * Base64url encoding strategy.
			     */
			    C_enc.Base64url = {
			        /**
			         * Converts a word array to a Base64url string.
			         *
			         * @param {WordArray} wordArray The word array.
			         *
			         * @param {boolean} urlSafe Whether to use url safe
			         *
			         * @return {string} The Base64url string.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var base64String = CryptoJS.enc.Base64url.stringify(wordArray);
			         */
			        stringify: function (wordArray, urlSafe=true) {
			            // Shortcuts
			            var words = wordArray.words;
			            var sigBytes = wordArray.sigBytes;
			            var map = urlSafe ? this._safe_map : this._map;

			            // Clamp excess bits
			            wordArray.clamp();

			            // Convert
			            var base64Chars = [];
			            for (var i = 0; i < sigBytes; i += 3) {
			                var byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
			                var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
			                var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

			                var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

			                for (var j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
			                    base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
			                }
			            }

			            // Add padding
			            var paddingChar = map.charAt(64);
			            if (paddingChar) {
			                while (base64Chars.length % 4) {
			                    base64Chars.push(paddingChar);
			                }
			            }

			            return base64Chars.join('');
			        },

			        /**
			         * Converts a Base64url string to a word array.
			         *
			         * @param {string} base64Str The Base64url string.
			         *
			         * @param {boolean} urlSafe Whether to use url safe
			         *
			         * @return {WordArray} The word array.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var wordArray = CryptoJS.enc.Base64url.parse(base64String);
			         */
			        parse: function (base64Str, urlSafe=true) {
			            // Shortcuts
			            var base64StrLength = base64Str.length;
			            var map = urlSafe ? this._safe_map : this._map;
			            var reverseMap = this._reverseMap;

			            if (!reverseMap) {
			                reverseMap = this._reverseMap = [];
			                for (var j = 0; j < map.length; j++) {
			                    reverseMap[map.charCodeAt(j)] = j;
			                }
			            }

			            // Ignore padding
			            var paddingChar = map.charAt(64);
			            if (paddingChar) {
			                var paddingIndex = base64Str.indexOf(paddingChar);
			                if (paddingIndex !== -1) {
			                    base64StrLength = paddingIndex;
			                }
			            }

			            // Convert
			            return parseLoop(base64Str, base64StrLength, reverseMap);

			        },

			        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
			        _safe_map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
			    };

			    function parseLoop(base64Str, base64StrLength, reverseMap) {
			        var words = [];
			        var nBytes = 0;
			        for (var i = 0; i < base64StrLength; i++) {
			            if (i % 4) {
			                var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
			                var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
			                var bitsCombined = bits1 | bits2;
			                words[nBytes >>> 2] |= bitsCombined << (24 - (nBytes % 4) * 8);
			                nBytes++;
			            }
			        }
			        return WordArray.create(words, nBytes);
			    }
			}());

			return CryptoJS.enc.Base64url;

		}));
} (encBase64url));
	return encBase64urlExports;
}

var md5Exports = {};
var md5 = {
  get exports(){ return md5Exports; },
  set exports(v){ md5Exports = v; },
};

var hasRequiredMd5;

function requireMd5 () {
	if (hasRequiredMd5) return md5Exports;
	hasRequiredMd5 = 1;
	(function (module, exports) {
(function (root, factory) {
			{
				// CommonJS
				module.exports = factory(requireCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function (Math) {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var WordArray = C_lib.WordArray;
			    var Hasher = C_lib.Hasher;
			    var C_algo = C.algo;

			    // Constants table
			    var T = [];

			    // Compute constants
			    (function () {
			        for (var i = 0; i < 64; i++) {
			            T[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;
			        }
			    }());

			    /**
			     * MD5 hash algorithm.
			     */
			    var MD5 = C_algo.MD5 = Hasher.extend({
			        _doReset: function () {
			            this._hash = new WordArray.init([
			                0x67452301, 0xefcdab89,
			                0x98badcfe, 0x10325476
			            ]);
			        },

			        _doProcessBlock: function (M, offset) {
			            // Swap endian
			            for (var i = 0; i < 16; i++) {
			                // Shortcuts
			                var offset_i = offset + i;
			                var M_offset_i = M[offset_i];

			                M[offset_i] = (
			                    (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
			                    (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
			                );
			            }

			            // Shortcuts
			            var H = this._hash.words;

			            var M_offset_0  = M[offset + 0];
			            var M_offset_1  = M[offset + 1];
			            var M_offset_2  = M[offset + 2];
			            var M_offset_3  = M[offset + 3];
			            var M_offset_4  = M[offset + 4];
			            var M_offset_5  = M[offset + 5];
			            var M_offset_6  = M[offset + 6];
			            var M_offset_7  = M[offset + 7];
			            var M_offset_8  = M[offset + 8];
			            var M_offset_9  = M[offset + 9];
			            var M_offset_10 = M[offset + 10];
			            var M_offset_11 = M[offset + 11];
			            var M_offset_12 = M[offset + 12];
			            var M_offset_13 = M[offset + 13];
			            var M_offset_14 = M[offset + 14];
			            var M_offset_15 = M[offset + 15];

			            // Working varialbes
			            var a = H[0];
			            var b = H[1];
			            var c = H[2];
			            var d = H[3];

			            // Computation
			            a = FF(a, b, c, d, M_offset_0,  7,  T[0]);
			            d = FF(d, a, b, c, M_offset_1,  12, T[1]);
			            c = FF(c, d, a, b, M_offset_2,  17, T[2]);
			            b = FF(b, c, d, a, M_offset_3,  22, T[3]);
			            a = FF(a, b, c, d, M_offset_4,  7,  T[4]);
			            d = FF(d, a, b, c, M_offset_5,  12, T[5]);
			            c = FF(c, d, a, b, M_offset_6,  17, T[6]);
			            b = FF(b, c, d, a, M_offset_7,  22, T[7]);
			            a = FF(a, b, c, d, M_offset_8,  7,  T[8]);
			            d = FF(d, a, b, c, M_offset_9,  12, T[9]);
			            c = FF(c, d, a, b, M_offset_10, 17, T[10]);
			            b = FF(b, c, d, a, M_offset_11, 22, T[11]);
			            a = FF(a, b, c, d, M_offset_12, 7,  T[12]);
			            d = FF(d, a, b, c, M_offset_13, 12, T[13]);
			            c = FF(c, d, a, b, M_offset_14, 17, T[14]);
			            b = FF(b, c, d, a, M_offset_15, 22, T[15]);

			            a = GG(a, b, c, d, M_offset_1,  5,  T[16]);
			            d = GG(d, a, b, c, M_offset_6,  9,  T[17]);
			            c = GG(c, d, a, b, M_offset_11, 14, T[18]);
			            b = GG(b, c, d, a, M_offset_0,  20, T[19]);
			            a = GG(a, b, c, d, M_offset_5,  5,  T[20]);
			            d = GG(d, a, b, c, M_offset_10, 9,  T[21]);
			            c = GG(c, d, a, b, M_offset_15, 14, T[22]);
			            b = GG(b, c, d, a, M_offset_4,  20, T[23]);
			            a = GG(a, b, c, d, M_offset_9,  5,  T[24]);
			            d = GG(d, a, b, c, M_offset_14, 9,  T[25]);
			            c = GG(c, d, a, b, M_offset_3,  14, T[26]);
			            b = GG(b, c, d, a, M_offset_8,  20, T[27]);
			            a = GG(a, b, c, d, M_offset_13, 5,  T[28]);
			            d = GG(d, a, b, c, M_offset_2,  9,  T[29]);
			            c = GG(c, d, a, b, M_offset_7,  14, T[30]);
			            b = GG(b, c, d, a, M_offset_12, 20, T[31]);

			            a = HH(a, b, c, d, M_offset_5,  4,  T[32]);
			            d = HH(d, a, b, c, M_offset_8,  11, T[33]);
			            c = HH(c, d, a, b, M_offset_11, 16, T[34]);
			            b = HH(b, c, d, a, M_offset_14, 23, T[35]);
			            a = HH(a, b, c, d, M_offset_1,  4,  T[36]);
			            d = HH(d, a, b, c, M_offset_4,  11, T[37]);
			            c = HH(c, d, a, b, M_offset_7,  16, T[38]);
			            b = HH(b, c, d, a, M_offset_10, 23, T[39]);
			            a = HH(a, b, c, d, M_offset_13, 4,  T[40]);
			            d = HH(d, a, b, c, M_offset_0,  11, T[41]);
			            c = HH(c, d, a, b, M_offset_3,  16, T[42]);
			            b = HH(b, c, d, a, M_offset_6,  23, T[43]);
			            a = HH(a, b, c, d, M_offset_9,  4,  T[44]);
			            d = HH(d, a, b, c, M_offset_12, 11, T[45]);
			            c = HH(c, d, a, b, M_offset_15, 16, T[46]);
			            b = HH(b, c, d, a, M_offset_2,  23, T[47]);

			            a = II(a, b, c, d, M_offset_0,  6,  T[48]);
			            d = II(d, a, b, c, M_offset_7,  10, T[49]);
			            c = II(c, d, a, b, M_offset_14, 15, T[50]);
			            b = II(b, c, d, a, M_offset_5,  21, T[51]);
			            a = II(a, b, c, d, M_offset_12, 6,  T[52]);
			            d = II(d, a, b, c, M_offset_3,  10, T[53]);
			            c = II(c, d, a, b, M_offset_10, 15, T[54]);
			            b = II(b, c, d, a, M_offset_1,  21, T[55]);
			            a = II(a, b, c, d, M_offset_8,  6,  T[56]);
			            d = II(d, a, b, c, M_offset_15, 10, T[57]);
			            c = II(c, d, a, b, M_offset_6,  15, T[58]);
			            b = II(b, c, d, a, M_offset_13, 21, T[59]);
			            a = II(a, b, c, d, M_offset_4,  6,  T[60]);
			            d = II(d, a, b, c, M_offset_11, 10, T[61]);
			            c = II(c, d, a, b, M_offset_2,  15, T[62]);
			            b = II(b, c, d, a, M_offset_9,  21, T[63]);

			            // Intermediate hash value
			            H[0] = (H[0] + a) | 0;
			            H[1] = (H[1] + b) | 0;
			            H[2] = (H[2] + c) | 0;
			            H[3] = (H[3] + d) | 0;
			        },

			        _doFinalize: function () {
			            // Shortcuts
			            var data = this._data;
			            var dataWords = data.words;

			            var nBitsTotal = this._nDataBytes * 8;
			            var nBitsLeft = data.sigBytes * 8;

			            // Add padding
			            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);

			            var nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
			            var nBitsTotalL = nBitsTotal;
			            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = (
			                (((nBitsTotalH << 8)  | (nBitsTotalH >>> 24)) & 0x00ff00ff) |
			                (((nBitsTotalH << 24) | (nBitsTotalH >>> 8))  & 0xff00ff00)
			            );
			            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
			                (((nBitsTotalL << 8)  | (nBitsTotalL >>> 24)) & 0x00ff00ff) |
			                (((nBitsTotalL << 24) | (nBitsTotalL >>> 8))  & 0xff00ff00)
			            );

			            data.sigBytes = (dataWords.length + 1) * 4;

			            // Hash final blocks
			            this._process();

			            // Shortcuts
			            var hash = this._hash;
			            var H = hash.words;

			            // Swap endian
			            for (var i = 0; i < 4; i++) {
			                // Shortcut
			                var H_i = H[i];

			                H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
			                       (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
			            }

			            // Return final computed hash
			            return hash;
			        },

			        clone: function () {
			            var clone = Hasher.clone.call(this);
			            clone._hash = this._hash.clone();

			            return clone;
			        }
			    });

			    function FF(a, b, c, d, x, s, t) {
			        var n = a + ((b & c) | (~b & d)) + x + t;
			        return ((n << s) | (n >>> (32 - s))) + b;
			    }

			    function GG(a, b, c, d, x, s, t) {
			        var n = a + ((b & d) | (c & ~d)) + x + t;
			        return ((n << s) | (n >>> (32 - s))) + b;
			    }

			    function HH(a, b, c, d, x, s, t) {
			        var n = a + (b ^ c ^ d) + x + t;
			        return ((n << s) | (n >>> (32 - s))) + b;
			    }

			    function II(a, b, c, d, x, s, t) {
			        var n = a + (c ^ (b | ~d)) + x + t;
			        return ((n << s) | (n >>> (32 - s))) + b;
			    }

			    /**
			     * Shortcut function to the hasher's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     *
			     * @return {WordArray} The hash.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hash = CryptoJS.MD5('message');
			     *     var hash = CryptoJS.MD5(wordArray);
			     */
			    C.MD5 = Hasher._createHelper(MD5);

			    /**
			     * Shortcut function to the HMAC's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     * @param {WordArray|string} key The secret key.
			     *
			     * @return {WordArray} The HMAC.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hmac = CryptoJS.HmacMD5(message, key);
			     */
			    C.HmacMD5 = Hasher._createHmacHelper(MD5);
			}(Math));


			return CryptoJS.MD5;

		}));
} (md5));
	return md5Exports;
}

var sha1Exports = {};
var sha1 = {
  get exports(){ return sha1Exports; },
  set exports(v){ sha1Exports = v; },
};

var hasRequiredSha1;

function requireSha1 () {
	if (hasRequiredSha1) return sha1Exports;
	hasRequiredSha1 = 1;
	(function (module, exports) {
(function (root, factory) {
			{
				// CommonJS
				module.exports = factory(requireCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var WordArray = C_lib.WordArray;
			    var Hasher = C_lib.Hasher;
			    var C_algo = C.algo;

			    // Reusable object
			    var W = [];

			    /**
			     * SHA-1 hash algorithm.
			     */
			    var SHA1 = C_algo.SHA1 = Hasher.extend({
			        _doReset: function () {
			            this._hash = new WordArray.init([
			                0x67452301, 0xefcdab89,
			                0x98badcfe, 0x10325476,
			                0xc3d2e1f0
			            ]);
			        },

			        _doProcessBlock: function (M, offset) {
			            // Shortcut
			            var H = this._hash.words;

			            // Working variables
			            var a = H[0];
			            var b = H[1];
			            var c = H[2];
			            var d = H[3];
			            var e = H[4];

			            // Computation
			            for (var i = 0; i < 80; i++) {
			                if (i < 16) {
			                    W[i] = M[offset + i] | 0;
			                } else {
			                    var n = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
			                    W[i] = (n << 1) | (n >>> 31);
			                }

			                var t = ((a << 5) | (a >>> 27)) + e + W[i];
			                if (i < 20) {
			                    t += ((b & c) | (~b & d)) + 0x5a827999;
			                } else if (i < 40) {
			                    t += (b ^ c ^ d) + 0x6ed9eba1;
			                } else if (i < 60) {
			                    t += ((b & c) | (b & d) | (c & d)) - 0x70e44324;
			                } else /* if (i < 80) */ {
			                    t += (b ^ c ^ d) - 0x359d3e2a;
			                }

			                e = d;
			                d = c;
			                c = (b << 30) | (b >>> 2);
			                b = a;
			                a = t;
			            }

			            // Intermediate hash value
			            H[0] = (H[0] + a) | 0;
			            H[1] = (H[1] + b) | 0;
			            H[2] = (H[2] + c) | 0;
			            H[3] = (H[3] + d) | 0;
			            H[4] = (H[4] + e) | 0;
			        },

			        _doFinalize: function () {
			            // Shortcuts
			            var data = this._data;
			            var dataWords = data.words;

			            var nBitsTotal = this._nDataBytes * 8;
			            var nBitsLeft = data.sigBytes * 8;

			            // Add padding
			            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
			            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
			            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
			            data.sigBytes = dataWords.length * 4;

			            // Hash final blocks
			            this._process();

			            // Return final computed hash
			            return this._hash;
			        },

			        clone: function () {
			            var clone = Hasher.clone.call(this);
			            clone._hash = this._hash.clone();

			            return clone;
			        }
			    });

			    /**
			     * Shortcut function to the hasher's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     *
			     * @return {WordArray} The hash.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hash = CryptoJS.SHA1('message');
			     *     var hash = CryptoJS.SHA1(wordArray);
			     */
			    C.SHA1 = Hasher._createHelper(SHA1);

			    /**
			     * Shortcut function to the HMAC's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     * @param {WordArray|string} key The secret key.
			     *
			     * @return {WordArray} The HMAC.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hmac = CryptoJS.HmacSHA1(message, key);
			     */
			    C.HmacSHA1 = Hasher._createHmacHelper(SHA1);
			}());


			return CryptoJS.SHA1;

		}));
} (sha1));
	return sha1Exports;
}

var sha256Exports = {};
var sha256 = {
  get exports(){ return sha256Exports; },
  set exports(v){ sha256Exports = v; },
};

var hasRequiredSha256;

function requireSha256 () {
	if (hasRequiredSha256) return sha256Exports;
	hasRequiredSha256 = 1;
	(function (module, exports) {
(function (root, factory) {
			{
				// CommonJS
				module.exports = factory(requireCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function (Math) {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var WordArray = C_lib.WordArray;
			    var Hasher = C_lib.Hasher;
			    var C_algo = C.algo;

			    // Initialization and round constants tables
			    var H = [];
			    var K = [];

			    // Compute constants
			    (function () {
			        function isPrime(n) {
			            var sqrtN = Math.sqrt(n);
			            for (var factor = 2; factor <= sqrtN; factor++) {
			                if (!(n % factor)) {
			                    return false;
			                }
			            }

			            return true;
			        }

			        function getFractionalBits(n) {
			            return ((n - (n | 0)) * 0x100000000) | 0;
			        }

			        var n = 2;
			        var nPrime = 0;
			        while (nPrime < 64) {
			            if (isPrime(n)) {
			                if (nPrime < 8) {
			                    H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
			                }
			                K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));

			                nPrime++;
			            }

			            n++;
			        }
			    }());

			    // Reusable object
			    var W = [];

			    /**
			     * SHA-256 hash algorithm.
			     */
			    var SHA256 = C_algo.SHA256 = Hasher.extend({
			        _doReset: function () {
			            this._hash = new WordArray.init(H.slice(0));
			        },

			        _doProcessBlock: function (M, offset) {
			            // Shortcut
			            var H = this._hash.words;

			            // Working variables
			            var a = H[0];
			            var b = H[1];
			            var c = H[2];
			            var d = H[3];
			            var e = H[4];
			            var f = H[5];
			            var g = H[6];
			            var h = H[7];

			            // Computation
			            for (var i = 0; i < 64; i++) {
			                if (i < 16) {
			                    W[i] = M[offset + i] | 0;
			                } else {
			                    var gamma0x = W[i - 15];
			                    var gamma0  = ((gamma0x << 25) | (gamma0x >>> 7))  ^
			                                  ((gamma0x << 14) | (gamma0x >>> 18)) ^
			                                   (gamma0x >>> 3);

			                    var gamma1x = W[i - 2];
			                    var gamma1  = ((gamma1x << 15) | (gamma1x >>> 17)) ^
			                                  ((gamma1x << 13) | (gamma1x >>> 19)) ^
			                                   (gamma1x >>> 10);

			                    W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
			                }

			                var ch  = (e & f) ^ (~e & g);
			                var maj = (a & b) ^ (a & c) ^ (b & c);

			                var sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
			                var sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7)  | (e >>> 25));

			                var t1 = h + sigma1 + ch + K[i] + W[i];
			                var t2 = sigma0 + maj;

			                h = g;
			                g = f;
			                f = e;
			                e = (d + t1) | 0;
			                d = c;
			                c = b;
			                b = a;
			                a = (t1 + t2) | 0;
			            }

			            // Intermediate hash value
			            H[0] = (H[0] + a) | 0;
			            H[1] = (H[1] + b) | 0;
			            H[2] = (H[2] + c) | 0;
			            H[3] = (H[3] + d) | 0;
			            H[4] = (H[4] + e) | 0;
			            H[5] = (H[5] + f) | 0;
			            H[6] = (H[6] + g) | 0;
			            H[7] = (H[7] + h) | 0;
			        },

			        _doFinalize: function () {
			            // Shortcuts
			            var data = this._data;
			            var dataWords = data.words;

			            var nBitsTotal = this._nDataBytes * 8;
			            var nBitsLeft = data.sigBytes * 8;

			            // Add padding
			            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
			            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
			            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
			            data.sigBytes = dataWords.length * 4;

			            // Hash final blocks
			            this._process();

			            // Return final computed hash
			            return this._hash;
			        },

			        clone: function () {
			            var clone = Hasher.clone.call(this);
			            clone._hash = this._hash.clone();

			            return clone;
			        }
			    });

			    /**
			     * Shortcut function to the hasher's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     *
			     * @return {WordArray} The hash.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hash = CryptoJS.SHA256('message');
			     *     var hash = CryptoJS.SHA256(wordArray);
			     */
			    C.SHA256 = Hasher._createHelper(SHA256);

			    /**
			     * Shortcut function to the HMAC's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     * @param {WordArray|string} key The secret key.
			     *
			     * @return {WordArray} The HMAC.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hmac = CryptoJS.HmacSHA256(message, key);
			     */
			    C.HmacSHA256 = Hasher._createHmacHelper(SHA256);
			}(Math));


			return CryptoJS.SHA256;

		}));
} (sha256));
	return sha256Exports;
}

var sha224Exports = {};
var sha224 = {
  get exports(){ return sha224Exports; },
  set exports(v){ sha224Exports = v; },
};

var hasRequiredSha224;

function requireSha224 () {
	if (hasRequiredSha224) return sha224Exports;
	hasRequiredSha224 = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireSha256());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var WordArray = C_lib.WordArray;
			    var C_algo = C.algo;
			    var SHA256 = C_algo.SHA256;

			    /**
			     * SHA-224 hash algorithm.
			     */
			    var SHA224 = C_algo.SHA224 = SHA256.extend({
			        _doReset: function () {
			            this._hash = new WordArray.init([
			                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
			                0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
			            ]);
			        },

			        _doFinalize: function () {
			            var hash = SHA256._doFinalize.call(this);

			            hash.sigBytes -= 4;

			            return hash;
			        }
			    });

			    /**
			     * Shortcut function to the hasher's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     *
			     * @return {WordArray} The hash.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hash = CryptoJS.SHA224('message');
			     *     var hash = CryptoJS.SHA224(wordArray);
			     */
			    C.SHA224 = SHA256._createHelper(SHA224);

			    /**
			     * Shortcut function to the HMAC's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     * @param {WordArray|string} key The secret key.
			     *
			     * @return {WordArray} The HMAC.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hmac = CryptoJS.HmacSHA224(message, key);
			     */
			    C.HmacSHA224 = SHA256._createHmacHelper(SHA224);
			}());


			return CryptoJS.SHA224;

		}));
} (sha224));
	return sha224Exports;
}

var sha512Exports = {};
var sha512 = {
  get exports(){ return sha512Exports; },
  set exports(v){ sha512Exports = v; },
};

var hasRequiredSha512;

function requireSha512 () {
	if (hasRequiredSha512) return sha512Exports;
	hasRequiredSha512 = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireX64Core());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var Hasher = C_lib.Hasher;
			    var C_x64 = C.x64;
			    var X64Word = C_x64.Word;
			    var X64WordArray = C_x64.WordArray;
			    var C_algo = C.algo;

			    function X64Word_create() {
			        return X64Word.create.apply(X64Word, arguments);
			    }

			    // Constants
			    var K = [
			        X64Word_create(0x428a2f98, 0xd728ae22), X64Word_create(0x71374491, 0x23ef65cd),
			        X64Word_create(0xb5c0fbcf, 0xec4d3b2f), X64Word_create(0xe9b5dba5, 0x8189dbbc),
			        X64Word_create(0x3956c25b, 0xf348b538), X64Word_create(0x59f111f1, 0xb605d019),
			        X64Word_create(0x923f82a4, 0xaf194f9b), X64Word_create(0xab1c5ed5, 0xda6d8118),
			        X64Word_create(0xd807aa98, 0xa3030242), X64Word_create(0x12835b01, 0x45706fbe),
			        X64Word_create(0x243185be, 0x4ee4b28c), X64Word_create(0x550c7dc3, 0xd5ffb4e2),
			        X64Word_create(0x72be5d74, 0xf27b896f), X64Word_create(0x80deb1fe, 0x3b1696b1),
			        X64Word_create(0x9bdc06a7, 0x25c71235), X64Word_create(0xc19bf174, 0xcf692694),
			        X64Word_create(0xe49b69c1, 0x9ef14ad2), X64Word_create(0xefbe4786, 0x384f25e3),
			        X64Word_create(0x0fc19dc6, 0x8b8cd5b5), X64Word_create(0x240ca1cc, 0x77ac9c65),
			        X64Word_create(0x2de92c6f, 0x592b0275), X64Word_create(0x4a7484aa, 0x6ea6e483),
			        X64Word_create(0x5cb0a9dc, 0xbd41fbd4), X64Word_create(0x76f988da, 0x831153b5),
			        X64Word_create(0x983e5152, 0xee66dfab), X64Word_create(0xa831c66d, 0x2db43210),
			        X64Word_create(0xb00327c8, 0x98fb213f), X64Word_create(0xbf597fc7, 0xbeef0ee4),
			        X64Word_create(0xc6e00bf3, 0x3da88fc2), X64Word_create(0xd5a79147, 0x930aa725),
			        X64Word_create(0x06ca6351, 0xe003826f), X64Word_create(0x14292967, 0x0a0e6e70),
			        X64Word_create(0x27b70a85, 0x46d22ffc), X64Word_create(0x2e1b2138, 0x5c26c926),
			        X64Word_create(0x4d2c6dfc, 0x5ac42aed), X64Word_create(0x53380d13, 0x9d95b3df),
			        X64Word_create(0x650a7354, 0x8baf63de), X64Word_create(0x766a0abb, 0x3c77b2a8),
			        X64Word_create(0x81c2c92e, 0x47edaee6), X64Word_create(0x92722c85, 0x1482353b),
			        X64Word_create(0xa2bfe8a1, 0x4cf10364), X64Word_create(0xa81a664b, 0xbc423001),
			        X64Word_create(0xc24b8b70, 0xd0f89791), X64Word_create(0xc76c51a3, 0x0654be30),
			        X64Word_create(0xd192e819, 0xd6ef5218), X64Word_create(0xd6990624, 0x5565a910),
			        X64Word_create(0xf40e3585, 0x5771202a), X64Word_create(0x106aa070, 0x32bbd1b8),
			        X64Word_create(0x19a4c116, 0xb8d2d0c8), X64Word_create(0x1e376c08, 0x5141ab53),
			        X64Word_create(0x2748774c, 0xdf8eeb99), X64Word_create(0x34b0bcb5, 0xe19b48a8),
			        X64Word_create(0x391c0cb3, 0xc5c95a63), X64Word_create(0x4ed8aa4a, 0xe3418acb),
			        X64Word_create(0x5b9cca4f, 0x7763e373), X64Word_create(0x682e6ff3, 0xd6b2b8a3),
			        X64Word_create(0x748f82ee, 0x5defb2fc), X64Word_create(0x78a5636f, 0x43172f60),
			        X64Word_create(0x84c87814, 0xa1f0ab72), X64Word_create(0x8cc70208, 0x1a6439ec),
			        X64Word_create(0x90befffa, 0x23631e28), X64Word_create(0xa4506ceb, 0xde82bde9),
			        X64Word_create(0xbef9a3f7, 0xb2c67915), X64Word_create(0xc67178f2, 0xe372532b),
			        X64Word_create(0xca273ece, 0xea26619c), X64Word_create(0xd186b8c7, 0x21c0c207),
			        X64Word_create(0xeada7dd6, 0xcde0eb1e), X64Word_create(0xf57d4f7f, 0xee6ed178),
			        X64Word_create(0x06f067aa, 0x72176fba), X64Word_create(0x0a637dc5, 0xa2c898a6),
			        X64Word_create(0x113f9804, 0xbef90dae), X64Word_create(0x1b710b35, 0x131c471b),
			        X64Word_create(0x28db77f5, 0x23047d84), X64Word_create(0x32caab7b, 0x40c72493),
			        X64Word_create(0x3c9ebe0a, 0x15c9bebc), X64Word_create(0x431d67c4, 0x9c100d4c),
			        X64Word_create(0x4cc5d4be, 0xcb3e42b6), X64Word_create(0x597f299c, 0xfc657e2a),
			        X64Word_create(0x5fcb6fab, 0x3ad6faec), X64Word_create(0x6c44198c, 0x4a475817)
			    ];

			    // Reusable objects
			    var W = [];
			    (function () {
			        for (var i = 0; i < 80; i++) {
			            W[i] = X64Word_create();
			        }
			    }());

			    /**
			     * SHA-512 hash algorithm.
			     */
			    var SHA512 = C_algo.SHA512 = Hasher.extend({
			        _doReset: function () {
			            this._hash = new X64WordArray.init([
			                new X64Word.init(0x6a09e667, 0xf3bcc908), new X64Word.init(0xbb67ae85, 0x84caa73b),
			                new X64Word.init(0x3c6ef372, 0xfe94f82b), new X64Word.init(0xa54ff53a, 0x5f1d36f1),
			                new X64Word.init(0x510e527f, 0xade682d1), new X64Word.init(0x9b05688c, 0x2b3e6c1f),
			                new X64Word.init(0x1f83d9ab, 0xfb41bd6b), new X64Word.init(0x5be0cd19, 0x137e2179)
			            ]);
			        },

			        _doProcessBlock: function (M, offset) {
			            // Shortcuts
			            var H = this._hash.words;

			            var H0 = H[0];
			            var H1 = H[1];
			            var H2 = H[2];
			            var H3 = H[3];
			            var H4 = H[4];
			            var H5 = H[5];
			            var H6 = H[6];
			            var H7 = H[7];

			            var H0h = H0.high;
			            var H0l = H0.low;
			            var H1h = H1.high;
			            var H1l = H1.low;
			            var H2h = H2.high;
			            var H2l = H2.low;
			            var H3h = H3.high;
			            var H3l = H3.low;
			            var H4h = H4.high;
			            var H4l = H4.low;
			            var H5h = H5.high;
			            var H5l = H5.low;
			            var H6h = H6.high;
			            var H6l = H6.low;
			            var H7h = H7.high;
			            var H7l = H7.low;

			            // Working variables
			            var ah = H0h;
			            var al = H0l;
			            var bh = H1h;
			            var bl = H1l;
			            var ch = H2h;
			            var cl = H2l;
			            var dh = H3h;
			            var dl = H3l;
			            var eh = H4h;
			            var el = H4l;
			            var fh = H5h;
			            var fl = H5l;
			            var gh = H6h;
			            var gl = H6l;
			            var hh = H7h;
			            var hl = H7l;

			            // Rounds
			            for (var i = 0; i < 80; i++) {
			                var Wil;
			                var Wih;

			                // Shortcut
			                var Wi = W[i];

			                // Extend message
			                if (i < 16) {
			                    Wih = Wi.high = M[offset + i * 2]     | 0;
			                    Wil = Wi.low  = M[offset + i * 2 + 1] | 0;
			                } else {
			                    // Gamma0
			                    var gamma0x  = W[i - 15];
			                    var gamma0xh = gamma0x.high;
			                    var gamma0xl = gamma0x.low;
			                    var gamma0h  = ((gamma0xh >>> 1) | (gamma0xl << 31)) ^ ((gamma0xh >>> 8) | (gamma0xl << 24)) ^ (gamma0xh >>> 7);
			                    var gamma0l  = ((gamma0xl >>> 1) | (gamma0xh << 31)) ^ ((gamma0xl >>> 8) | (gamma0xh << 24)) ^ ((gamma0xl >>> 7) | (gamma0xh << 25));

			                    // Gamma1
			                    var gamma1x  = W[i - 2];
			                    var gamma1xh = gamma1x.high;
			                    var gamma1xl = gamma1x.low;
			                    var gamma1h  = ((gamma1xh >>> 19) | (gamma1xl << 13)) ^ ((gamma1xh << 3) | (gamma1xl >>> 29)) ^ (gamma1xh >>> 6);
			                    var gamma1l  = ((gamma1xl >>> 19) | (gamma1xh << 13)) ^ ((gamma1xl << 3) | (gamma1xh >>> 29)) ^ ((gamma1xl >>> 6) | (gamma1xh << 26));

			                    // W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16]
			                    var Wi7  = W[i - 7];
			                    var Wi7h = Wi7.high;
			                    var Wi7l = Wi7.low;

			                    var Wi16  = W[i - 16];
			                    var Wi16h = Wi16.high;
			                    var Wi16l = Wi16.low;

			                    Wil = gamma0l + Wi7l;
			                    Wih = gamma0h + Wi7h + ((Wil >>> 0) < (gamma0l >>> 0) ? 1 : 0);
			                    Wil = Wil + gamma1l;
			                    Wih = Wih + gamma1h + ((Wil >>> 0) < (gamma1l >>> 0) ? 1 : 0);
			                    Wil = Wil + Wi16l;
			                    Wih = Wih + Wi16h + ((Wil >>> 0) < (Wi16l >>> 0) ? 1 : 0);

			                    Wi.high = Wih;
			                    Wi.low  = Wil;
			                }

			                var chh  = (eh & fh) ^ (~eh & gh);
			                var chl  = (el & fl) ^ (~el & gl);
			                var majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
			                var majl = (al & bl) ^ (al & cl) ^ (bl & cl);

			                var sigma0h = ((ah >>> 28) | (al << 4))  ^ ((ah << 30)  | (al >>> 2)) ^ ((ah << 25) | (al >>> 7));
			                var sigma0l = ((al >>> 28) | (ah << 4))  ^ ((al << 30)  | (ah >>> 2)) ^ ((al << 25) | (ah >>> 7));
			                var sigma1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9));
			                var sigma1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9));

			                // t1 = h + sigma1 + ch + K[i] + W[i]
			                var Ki  = K[i];
			                var Kih = Ki.high;
			                var Kil = Ki.low;

			                var t1l = hl + sigma1l;
			                var t1h = hh + sigma1h + ((t1l >>> 0) < (hl >>> 0) ? 1 : 0);
			                var t1l = t1l + chl;
			                var t1h = t1h + chh + ((t1l >>> 0) < (chl >>> 0) ? 1 : 0);
			                var t1l = t1l + Kil;
			                var t1h = t1h + Kih + ((t1l >>> 0) < (Kil >>> 0) ? 1 : 0);
			                var t1l = t1l + Wil;
			                var t1h = t1h + Wih + ((t1l >>> 0) < (Wil >>> 0) ? 1 : 0);

			                // t2 = sigma0 + maj
			                var t2l = sigma0l + majl;
			                var t2h = sigma0h + majh + ((t2l >>> 0) < (sigma0l >>> 0) ? 1 : 0);

			                // Update working variables
			                hh = gh;
			                hl = gl;
			                gh = fh;
			                gl = fl;
			                fh = eh;
			                fl = el;
			                el = (dl + t1l) | 0;
			                eh = (dh + t1h + ((el >>> 0) < (dl >>> 0) ? 1 : 0)) | 0;
			                dh = ch;
			                dl = cl;
			                ch = bh;
			                cl = bl;
			                bh = ah;
			                bl = al;
			                al = (t1l + t2l) | 0;
			                ah = (t1h + t2h + ((al >>> 0) < (t1l >>> 0) ? 1 : 0)) | 0;
			            }

			            // Intermediate hash value
			            H0l = H0.low  = (H0l + al);
			            H0.high = (H0h + ah + ((H0l >>> 0) < (al >>> 0) ? 1 : 0));
			            H1l = H1.low  = (H1l + bl);
			            H1.high = (H1h + bh + ((H1l >>> 0) < (bl >>> 0) ? 1 : 0));
			            H2l = H2.low  = (H2l + cl);
			            H2.high = (H2h + ch + ((H2l >>> 0) < (cl >>> 0) ? 1 : 0));
			            H3l = H3.low  = (H3l + dl);
			            H3.high = (H3h + dh + ((H3l >>> 0) < (dl >>> 0) ? 1 : 0));
			            H4l = H4.low  = (H4l + el);
			            H4.high = (H4h + eh + ((H4l >>> 0) < (el >>> 0) ? 1 : 0));
			            H5l = H5.low  = (H5l + fl);
			            H5.high = (H5h + fh + ((H5l >>> 0) < (fl >>> 0) ? 1 : 0));
			            H6l = H6.low  = (H6l + gl);
			            H6.high = (H6h + gh + ((H6l >>> 0) < (gl >>> 0) ? 1 : 0));
			            H7l = H7.low  = (H7l + hl);
			            H7.high = (H7h + hh + ((H7l >>> 0) < (hl >>> 0) ? 1 : 0));
			        },

			        _doFinalize: function () {
			            // Shortcuts
			            var data = this._data;
			            var dataWords = data.words;

			            var nBitsTotal = this._nDataBytes * 8;
			            var nBitsLeft = data.sigBytes * 8;

			            // Add padding
			            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
			            dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 30] = Math.floor(nBitsTotal / 0x100000000);
			            dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 31] = nBitsTotal;
			            data.sigBytes = dataWords.length * 4;

			            // Hash final blocks
			            this._process();

			            // Convert hash to 32-bit word array before returning
			            var hash = this._hash.toX32();

			            // Return final computed hash
			            return hash;
			        },

			        clone: function () {
			            var clone = Hasher.clone.call(this);
			            clone._hash = this._hash.clone();

			            return clone;
			        },

			        blockSize: 1024/32
			    });

			    /**
			     * Shortcut function to the hasher's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     *
			     * @return {WordArray} The hash.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hash = CryptoJS.SHA512('message');
			     *     var hash = CryptoJS.SHA512(wordArray);
			     */
			    C.SHA512 = Hasher._createHelper(SHA512);

			    /**
			     * Shortcut function to the HMAC's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     * @param {WordArray|string} key The secret key.
			     *
			     * @return {WordArray} The HMAC.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hmac = CryptoJS.HmacSHA512(message, key);
			     */
			    C.HmacSHA512 = Hasher._createHmacHelper(SHA512);
			}());


			return CryptoJS.SHA512;

		}));
} (sha512));
	return sha512Exports;
}

var sha384Exports = {};
var sha384 = {
  get exports(){ return sha384Exports; },
  set exports(v){ sha384Exports = v; },
};

var hasRequiredSha384;

function requireSha384 () {
	if (hasRequiredSha384) return sha384Exports;
	hasRequiredSha384 = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireX64Core(), requireSha512());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_x64 = C.x64;
			    var X64Word = C_x64.Word;
			    var X64WordArray = C_x64.WordArray;
			    var C_algo = C.algo;
			    var SHA512 = C_algo.SHA512;

			    /**
			     * SHA-384 hash algorithm.
			     */
			    var SHA384 = C_algo.SHA384 = SHA512.extend({
			        _doReset: function () {
			            this._hash = new X64WordArray.init([
			                new X64Word.init(0xcbbb9d5d, 0xc1059ed8), new X64Word.init(0x629a292a, 0x367cd507),
			                new X64Word.init(0x9159015a, 0x3070dd17), new X64Word.init(0x152fecd8, 0xf70e5939),
			                new X64Word.init(0x67332667, 0xffc00b31), new X64Word.init(0x8eb44a87, 0x68581511),
			                new X64Word.init(0xdb0c2e0d, 0x64f98fa7), new X64Word.init(0x47b5481d, 0xbefa4fa4)
			            ]);
			        },

			        _doFinalize: function () {
			            var hash = SHA512._doFinalize.call(this);

			            hash.sigBytes -= 16;

			            return hash;
			        }
			    });

			    /**
			     * Shortcut function to the hasher's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     *
			     * @return {WordArray} The hash.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hash = CryptoJS.SHA384('message');
			     *     var hash = CryptoJS.SHA384(wordArray);
			     */
			    C.SHA384 = SHA512._createHelper(SHA384);

			    /**
			     * Shortcut function to the HMAC's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     * @param {WordArray|string} key The secret key.
			     *
			     * @return {WordArray} The HMAC.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hmac = CryptoJS.HmacSHA384(message, key);
			     */
			    C.HmacSHA384 = SHA512._createHmacHelper(SHA384);
			}());


			return CryptoJS.SHA384;

		}));
} (sha384));
	return sha384Exports;
}

var sha3Exports = {};
var sha3 = {
  get exports(){ return sha3Exports; },
  set exports(v){ sha3Exports = v; },
};

var hasRequiredSha3;

function requireSha3 () {
	if (hasRequiredSha3) return sha3Exports;
	hasRequiredSha3 = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireX64Core());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function (Math) {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var WordArray = C_lib.WordArray;
			    var Hasher = C_lib.Hasher;
			    var C_x64 = C.x64;
			    var X64Word = C_x64.Word;
			    var C_algo = C.algo;

			    // Constants tables
			    var RHO_OFFSETS = [];
			    var PI_INDEXES  = [];
			    var ROUND_CONSTANTS = [];

			    // Compute Constants
			    (function () {
			        // Compute rho offset constants
			        var x = 1, y = 0;
			        for (var t = 0; t < 24; t++) {
			            RHO_OFFSETS[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;

			            var newX = y % 5;
			            var newY = (2 * x + 3 * y) % 5;
			            x = newX;
			            y = newY;
			        }

			        // Compute pi index constants
			        for (var x = 0; x < 5; x++) {
			            for (var y = 0; y < 5; y++) {
			                PI_INDEXES[x + 5 * y] = y + ((2 * x + 3 * y) % 5) * 5;
			            }
			        }

			        // Compute round constants
			        var LFSR = 0x01;
			        for (var i = 0; i < 24; i++) {
			            var roundConstantMsw = 0;
			            var roundConstantLsw = 0;

			            for (var j = 0; j < 7; j++) {
			                if (LFSR & 0x01) {
			                    var bitPosition = (1 << j) - 1;
			                    if (bitPosition < 32) {
			                        roundConstantLsw ^= 1 << bitPosition;
			                    } else /* if (bitPosition >= 32) */ {
			                        roundConstantMsw ^= 1 << (bitPosition - 32);
			                    }
			                }

			                // Compute next LFSR
			                if (LFSR & 0x80) {
			                    // Primitive polynomial over GF(2): x^8 + x^6 + x^5 + x^4 + 1
			                    LFSR = (LFSR << 1) ^ 0x71;
			                } else {
			                    LFSR <<= 1;
			                }
			            }

			            ROUND_CONSTANTS[i] = X64Word.create(roundConstantMsw, roundConstantLsw);
			        }
			    }());

			    // Reusable objects for temporary values
			    var T = [];
			    (function () {
			        for (var i = 0; i < 25; i++) {
			            T[i] = X64Word.create();
			        }
			    }());

			    /**
			     * SHA-3 hash algorithm.
			     */
			    var SHA3 = C_algo.SHA3 = Hasher.extend({
			        /**
			         * Configuration options.
			         *
			         * @property {number} outputLength
			         *   The desired number of bits in the output hash.
			         *   Only values permitted are: 224, 256, 384, 512.
			         *   Default: 512
			         */
			        cfg: Hasher.cfg.extend({
			            outputLength: 512
			        }),

			        _doReset: function () {
			            var state = this._state = [];
			            for (var i = 0; i < 25; i++) {
			                state[i] = new X64Word.init();
			            }

			            this.blockSize = (1600 - 2 * this.cfg.outputLength) / 32;
			        },

			        _doProcessBlock: function (M, offset) {
			            // Shortcuts
			            var state = this._state;
			            var nBlockSizeLanes = this.blockSize / 2;

			            // Absorb
			            for (var i = 0; i < nBlockSizeLanes; i++) {
			                // Shortcuts
			                var M2i  = M[offset + 2 * i];
			                var M2i1 = M[offset + 2 * i + 1];

			                // Swap endian
			                M2i = (
			                    (((M2i << 8)  | (M2i >>> 24)) & 0x00ff00ff) |
			                    (((M2i << 24) | (M2i >>> 8))  & 0xff00ff00)
			                );
			                M2i1 = (
			                    (((M2i1 << 8)  | (M2i1 >>> 24)) & 0x00ff00ff) |
			                    (((M2i1 << 24) | (M2i1 >>> 8))  & 0xff00ff00)
			                );

			                // Absorb message into state
			                var lane = state[i];
			                lane.high ^= M2i1;
			                lane.low  ^= M2i;
			            }

			            // Rounds
			            for (var round = 0; round < 24; round++) {
			                // Theta
			                for (var x = 0; x < 5; x++) {
			                    // Mix column lanes
			                    var tMsw = 0, tLsw = 0;
			                    for (var y = 0; y < 5; y++) {
			                        var lane = state[x + 5 * y];
			                        tMsw ^= lane.high;
			                        tLsw ^= lane.low;
			                    }

			                    // Temporary values
			                    var Tx = T[x];
			                    Tx.high = tMsw;
			                    Tx.low  = tLsw;
			                }
			                for (var x = 0; x < 5; x++) {
			                    // Shortcuts
			                    var Tx4 = T[(x + 4) % 5];
			                    var Tx1 = T[(x + 1) % 5];
			                    var Tx1Msw = Tx1.high;
			                    var Tx1Lsw = Tx1.low;

			                    // Mix surrounding columns
			                    var tMsw = Tx4.high ^ ((Tx1Msw << 1) | (Tx1Lsw >>> 31));
			                    var tLsw = Tx4.low  ^ ((Tx1Lsw << 1) | (Tx1Msw >>> 31));
			                    for (var y = 0; y < 5; y++) {
			                        var lane = state[x + 5 * y];
			                        lane.high ^= tMsw;
			                        lane.low  ^= tLsw;
			                    }
			                }

			                // Rho Pi
			                for (var laneIndex = 1; laneIndex < 25; laneIndex++) {
			                    var tMsw;
			                    var tLsw;

			                    // Shortcuts
			                    var lane = state[laneIndex];
			                    var laneMsw = lane.high;
			                    var laneLsw = lane.low;
			                    var rhoOffset = RHO_OFFSETS[laneIndex];

			                    // Rotate lanes
			                    if (rhoOffset < 32) {
			                        tMsw = (laneMsw << rhoOffset) | (laneLsw >>> (32 - rhoOffset));
			                        tLsw = (laneLsw << rhoOffset) | (laneMsw >>> (32 - rhoOffset));
			                    } else /* if (rhoOffset >= 32) */ {
			                        tMsw = (laneLsw << (rhoOffset - 32)) | (laneMsw >>> (64 - rhoOffset));
			                        tLsw = (laneMsw << (rhoOffset - 32)) | (laneLsw >>> (64 - rhoOffset));
			                    }

			                    // Transpose lanes
			                    var TPiLane = T[PI_INDEXES[laneIndex]];
			                    TPiLane.high = tMsw;
			                    TPiLane.low  = tLsw;
			                }

			                // Rho pi at x = y = 0
			                var T0 = T[0];
			                var state0 = state[0];
			                T0.high = state0.high;
			                T0.low  = state0.low;

			                // Chi
			                for (var x = 0; x < 5; x++) {
			                    for (var y = 0; y < 5; y++) {
			                        // Shortcuts
			                        var laneIndex = x + 5 * y;
			                        var lane = state[laneIndex];
			                        var TLane = T[laneIndex];
			                        var Tx1Lane = T[((x + 1) % 5) + 5 * y];
			                        var Tx2Lane = T[((x + 2) % 5) + 5 * y];

			                        // Mix rows
			                        lane.high = TLane.high ^ (~Tx1Lane.high & Tx2Lane.high);
			                        lane.low  = TLane.low  ^ (~Tx1Lane.low  & Tx2Lane.low);
			                    }
			                }

			                // Iota
			                var lane = state[0];
			                var roundConstant = ROUND_CONSTANTS[round];
			                lane.high ^= roundConstant.high;
			                lane.low  ^= roundConstant.low;
			            }
			        },

			        _doFinalize: function () {
			            // Shortcuts
			            var data = this._data;
			            var dataWords = data.words;
			            this._nDataBytes * 8;
			            var nBitsLeft = data.sigBytes * 8;
			            var blockSizeBits = this.blockSize * 32;

			            // Add padding
			            dataWords[nBitsLeft >>> 5] |= 0x1 << (24 - nBitsLeft % 32);
			            dataWords[((Math.ceil((nBitsLeft + 1) / blockSizeBits) * blockSizeBits) >>> 5) - 1] |= 0x80;
			            data.sigBytes = dataWords.length * 4;

			            // Hash final blocks
			            this._process();

			            // Shortcuts
			            var state = this._state;
			            var outputLengthBytes = this.cfg.outputLength / 8;
			            var outputLengthLanes = outputLengthBytes / 8;

			            // Squeeze
			            var hashWords = [];
			            for (var i = 0; i < outputLengthLanes; i++) {
			                // Shortcuts
			                var lane = state[i];
			                var laneMsw = lane.high;
			                var laneLsw = lane.low;

			                // Swap endian
			                laneMsw = (
			                    (((laneMsw << 8)  | (laneMsw >>> 24)) & 0x00ff00ff) |
			                    (((laneMsw << 24) | (laneMsw >>> 8))  & 0xff00ff00)
			                );
			                laneLsw = (
			                    (((laneLsw << 8)  | (laneLsw >>> 24)) & 0x00ff00ff) |
			                    (((laneLsw << 24) | (laneLsw >>> 8))  & 0xff00ff00)
			                );

			                // Squeeze state to retrieve hash
			                hashWords.push(laneLsw);
			                hashWords.push(laneMsw);
			            }

			            // Return final computed hash
			            return new WordArray.init(hashWords, outputLengthBytes);
			        },

			        clone: function () {
			            var clone = Hasher.clone.call(this);

			            var state = clone._state = this._state.slice(0);
			            for (var i = 0; i < 25; i++) {
			                state[i] = state[i].clone();
			            }

			            return clone;
			        }
			    });

			    /**
			     * Shortcut function to the hasher's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     *
			     * @return {WordArray} The hash.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hash = CryptoJS.SHA3('message');
			     *     var hash = CryptoJS.SHA3(wordArray);
			     */
			    C.SHA3 = Hasher._createHelper(SHA3);

			    /**
			     * Shortcut function to the HMAC's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     * @param {WordArray|string} key The secret key.
			     *
			     * @return {WordArray} The HMAC.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hmac = CryptoJS.HmacSHA3(message, key);
			     */
			    C.HmacSHA3 = Hasher._createHmacHelper(SHA3);
			}(Math));


			return CryptoJS.SHA3;

		}));
} (sha3));
	return sha3Exports;
}

var ripemd160Exports = {};
var ripemd160 = {
  get exports(){ return ripemd160Exports; },
  set exports(v){ ripemd160Exports = v; },
};

var hasRequiredRipemd160;

function requireRipemd160 () {
	if (hasRequiredRipemd160) return ripemd160Exports;
	hasRequiredRipemd160 = 1;
	(function (module, exports) {
(function (root, factory) {
			{
				// CommonJS
				module.exports = factory(requireCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			/** @preserve
			(c) 2012 by Cédric Mesnil. All rights reserved.

			Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

			    - Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
			    - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

			THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
			*/

			(function (Math) {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var WordArray = C_lib.WordArray;
			    var Hasher = C_lib.Hasher;
			    var C_algo = C.algo;

			    // Constants table
			    var _zl = WordArray.create([
			        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
			        7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
			        3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
			        1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
			        4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13]);
			    var _zr = WordArray.create([
			        5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
			        6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
			        15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
			        8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
			        12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11]);
			    var _sl = WordArray.create([
			         11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
			        7, 6,   8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
			        11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
			          11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
			        9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 ]);
			    var _sr = WordArray.create([
			        8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
			        9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
			        9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
			        15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
			        8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 ]);

			    var _hl =  WordArray.create([ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]);
			    var _hr =  WordArray.create([ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]);

			    /**
			     * RIPEMD160 hash algorithm.
			     */
			    var RIPEMD160 = C_algo.RIPEMD160 = Hasher.extend({
			        _doReset: function () {
			            this._hash  = WordArray.create([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
			        },

			        _doProcessBlock: function (M, offset) {

			            // Swap endian
			            for (var i = 0; i < 16; i++) {
			                // Shortcuts
			                var offset_i = offset + i;
			                var M_offset_i = M[offset_i];

			                // Swap
			                M[offset_i] = (
			                    (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
			                    (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
			                );
			            }
			            // Shortcut
			            var H  = this._hash.words;
			            var hl = _hl.words;
			            var hr = _hr.words;
			            var zl = _zl.words;
			            var zr = _zr.words;
			            var sl = _sl.words;
			            var sr = _sr.words;

			            // Working variables
			            var al, bl, cl, dl, el;
			            var ar, br, cr, dr, er;

			            ar = al = H[0];
			            br = bl = H[1];
			            cr = cl = H[2];
			            dr = dl = H[3];
			            er = el = H[4];
			            // Computation
			            var t;
			            for (var i = 0; i < 80; i += 1) {
			                t = (al +  M[offset+zl[i]])|0;
			                if (i<16){
				            t +=  f1(bl,cl,dl) + hl[0];
			                } else if (i<32) {
				            t +=  f2(bl,cl,dl) + hl[1];
			                } else if (i<48) {
				            t +=  f3(bl,cl,dl) + hl[2];
			                } else if (i<64) {
				            t +=  f4(bl,cl,dl) + hl[3];
			                } else {// if (i<80) {
				            t +=  f5(bl,cl,dl) + hl[4];
			                }
			                t = t|0;
			                t =  rotl(t,sl[i]);
			                t = (t+el)|0;
			                al = el;
			                el = dl;
			                dl = rotl(cl, 10);
			                cl = bl;
			                bl = t;

			                t = (ar + M[offset+zr[i]])|0;
			                if (i<16){
				            t +=  f5(br,cr,dr) + hr[0];
			                } else if (i<32) {
				            t +=  f4(br,cr,dr) + hr[1];
			                } else if (i<48) {
				            t +=  f3(br,cr,dr) + hr[2];
			                } else if (i<64) {
				            t +=  f2(br,cr,dr) + hr[3];
			                } else {// if (i<80) {
				            t +=  f1(br,cr,dr) + hr[4];
			                }
			                t = t|0;
			                t =  rotl(t,sr[i]) ;
			                t = (t+er)|0;
			                ar = er;
			                er = dr;
			                dr = rotl(cr, 10);
			                cr = br;
			                br = t;
			            }
			            // Intermediate hash value
			            t    = (H[1] + cl + dr)|0;
			            H[1] = (H[2] + dl + er)|0;
			            H[2] = (H[3] + el + ar)|0;
			            H[3] = (H[4] + al + br)|0;
			            H[4] = (H[0] + bl + cr)|0;
			            H[0] =  t;
			        },

			        _doFinalize: function () {
			            // Shortcuts
			            var data = this._data;
			            var dataWords = data.words;

			            var nBitsTotal = this._nDataBytes * 8;
			            var nBitsLeft = data.sigBytes * 8;

			            // Add padding
			            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
			            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
			                (((nBitsTotal << 8)  | (nBitsTotal >>> 24)) & 0x00ff00ff) |
			                (((nBitsTotal << 24) | (nBitsTotal >>> 8))  & 0xff00ff00)
			            );
			            data.sigBytes = (dataWords.length + 1) * 4;

			            // Hash final blocks
			            this._process();

			            // Shortcuts
			            var hash = this._hash;
			            var H = hash.words;

			            // Swap endian
			            for (var i = 0; i < 5; i++) {
			                // Shortcut
			                var H_i = H[i];

			                // Swap
			                H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
			                       (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
			            }

			            // Return final computed hash
			            return hash;
			        },

			        clone: function () {
			            var clone = Hasher.clone.call(this);
			            clone._hash = this._hash.clone();

			            return clone;
			        }
			    });


			    function f1(x, y, z) {
			        return ((x) ^ (y) ^ (z));

			    }

			    function f2(x, y, z) {
			        return (((x)&(y)) | ((~x)&(z)));
			    }

			    function f3(x, y, z) {
			        return (((x) | (~(y))) ^ (z));
			    }

			    function f4(x, y, z) {
			        return (((x) & (z)) | ((y)&(~(z))));
			    }

			    function f5(x, y, z) {
			        return ((x) ^ ((y) |(~(z))));

			    }

			    function rotl(x,n) {
			        return (x<<n) | (x>>>(32-n));
			    }


			    /**
			     * Shortcut function to the hasher's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     *
			     * @return {WordArray} The hash.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hash = CryptoJS.RIPEMD160('message');
			     *     var hash = CryptoJS.RIPEMD160(wordArray);
			     */
			    C.RIPEMD160 = Hasher._createHelper(RIPEMD160);

			    /**
			     * Shortcut function to the HMAC's object interface.
			     *
			     * @param {WordArray|string} message The message to hash.
			     * @param {WordArray|string} key The secret key.
			     *
			     * @return {WordArray} The HMAC.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var hmac = CryptoJS.HmacRIPEMD160(message, key);
			     */
			    C.HmacRIPEMD160 = Hasher._createHmacHelper(RIPEMD160);
			}());


			return CryptoJS.RIPEMD160;

		}));
} (ripemd160));
	return ripemd160Exports;
}

var hmacExports = {};
var hmac = {
  get exports(){ return hmacExports; },
  set exports(v){ hmacExports = v; },
};

var hasRequiredHmac;

function requireHmac () {
	if (hasRequiredHmac) return hmacExports;
	hasRequiredHmac = 1;
	(function (module, exports) {
(function (root, factory) {
			{
				// CommonJS
				module.exports = factory(requireCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var Base = C_lib.Base;
			    var C_enc = C.enc;
			    var Utf8 = C_enc.Utf8;
			    var C_algo = C.algo;

			    /**
			     * HMAC algorithm.
			     */
			    C_algo.HMAC = Base.extend({
			        /**
			         * Initializes a newly created HMAC.
			         *
			         * @param {Hasher} hasher The hash algorithm to use.
			         * @param {WordArray|string} key The secret key.
			         *
			         * @example
			         *
			         *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
			         */
			        init: function (hasher, key) {
			            // Init hasher
			            hasher = this._hasher = new hasher.init();

			            // Convert string to WordArray, else assume WordArray already
			            if (typeof key == 'string') {
			                key = Utf8.parse(key);
			            }

			            // Shortcuts
			            var hasherBlockSize = hasher.blockSize;
			            var hasherBlockSizeBytes = hasherBlockSize * 4;

			            // Allow arbitrary length keys
			            if (key.sigBytes > hasherBlockSizeBytes) {
			                key = hasher.finalize(key);
			            }

			            // Clamp excess bits
			            key.clamp();

			            // Clone key for inner and outer pads
			            var oKey = this._oKey = key.clone();
			            var iKey = this._iKey = key.clone();

			            // Shortcuts
			            var oKeyWords = oKey.words;
			            var iKeyWords = iKey.words;

			            // XOR keys with pad constants
			            for (var i = 0; i < hasherBlockSize; i++) {
			                oKeyWords[i] ^= 0x5c5c5c5c;
			                iKeyWords[i] ^= 0x36363636;
			            }
			            oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;

			            // Set initial values
			            this.reset();
			        },

			        /**
			         * Resets this HMAC to its initial state.
			         *
			         * @example
			         *
			         *     hmacHasher.reset();
			         */
			        reset: function () {
			            // Shortcut
			            var hasher = this._hasher;

			            // Reset
			            hasher.reset();
			            hasher.update(this._iKey);
			        },

			        /**
			         * Updates this HMAC with a message.
			         *
			         * @param {WordArray|string} messageUpdate The message to append.
			         *
			         * @return {HMAC} This HMAC instance.
			         *
			         * @example
			         *
			         *     hmacHasher.update('message');
			         *     hmacHasher.update(wordArray);
			         */
			        update: function (messageUpdate) {
			            this._hasher.update(messageUpdate);

			            // Chainable
			            return this;
			        },

			        /**
			         * Finalizes the HMAC computation.
			         * Note that the finalize operation is effectively a destructive, read-once operation.
			         *
			         * @param {WordArray|string} messageUpdate (Optional) A final message update.
			         *
			         * @return {WordArray} The HMAC.
			         *
			         * @example
			         *
			         *     var hmac = hmacHasher.finalize();
			         *     var hmac = hmacHasher.finalize('message');
			         *     var hmac = hmacHasher.finalize(wordArray);
			         */
			        finalize: function (messageUpdate) {
			            // Shortcut
			            var hasher = this._hasher;

			            // Compute HMAC
			            var innerHash = hasher.finalize(messageUpdate);
			            hasher.reset();
			            var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));

			            return hmac;
			        }
			    });
			}());


		}));
} (hmac));
	return hmacExports;
}

var pbkdf2Exports = {};
var pbkdf2 = {
  get exports(){ return pbkdf2Exports; },
  set exports(v){ pbkdf2Exports = v; },
};

var hasRequiredPbkdf2;

function requirePbkdf2 () {
	if (hasRequiredPbkdf2) return pbkdf2Exports;
	hasRequiredPbkdf2 = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireSha1(), requireHmac());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var Base = C_lib.Base;
			    var WordArray = C_lib.WordArray;
			    var C_algo = C.algo;
			    var SHA1 = C_algo.SHA1;
			    var HMAC = C_algo.HMAC;

			    /**
			     * Password-Based Key Derivation Function 2 algorithm.
			     */
			    var PBKDF2 = C_algo.PBKDF2 = Base.extend({
			        /**
			         * Configuration options.
			         *
			         * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
			         * @property {Hasher} hasher The hasher to use. Default: SHA1
			         * @property {number} iterations The number of iterations to perform. Default: 1
			         */
			        cfg: Base.extend({
			            keySize: 128/32,
			            hasher: SHA1,
			            iterations: 1
			        }),

			        /**
			         * Initializes a newly created key derivation function.
			         *
			         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
			         *
			         * @example
			         *
			         *     var kdf = CryptoJS.algo.PBKDF2.create();
			         *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8 });
			         *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8, iterations: 1000 });
			         */
			        init: function (cfg) {
			            this.cfg = this.cfg.extend(cfg);
			        },

			        /**
			         * Computes the Password-Based Key Derivation Function 2.
			         *
			         * @param {WordArray|string} password The password.
			         * @param {WordArray|string} salt A salt.
			         *
			         * @return {WordArray} The derived key.
			         *
			         * @example
			         *
			         *     var key = kdf.compute(password, salt);
			         */
			        compute: function (password, salt) {
			            // Shortcut
			            var cfg = this.cfg;

			            // Init HMAC
			            var hmac = HMAC.create(cfg.hasher, password);

			            // Initial values
			            var derivedKey = WordArray.create();
			            var blockIndex = WordArray.create([0x00000001]);

			            // Shortcuts
			            var derivedKeyWords = derivedKey.words;
			            var blockIndexWords = blockIndex.words;
			            var keySize = cfg.keySize;
			            var iterations = cfg.iterations;

			            // Generate key
			            while (derivedKeyWords.length < keySize) {
			                var block = hmac.update(salt).finalize(blockIndex);
			                hmac.reset();

			                // Shortcuts
			                var blockWords = block.words;
			                var blockWordsLength = blockWords.length;

			                // Iterations
			                var intermediate = block;
			                for (var i = 1; i < iterations; i++) {
			                    intermediate = hmac.finalize(intermediate);
			                    hmac.reset();

			                    // Shortcut
			                    var intermediateWords = intermediate.words;

			                    // XOR intermediate with block
			                    for (var j = 0; j < blockWordsLength; j++) {
			                        blockWords[j] ^= intermediateWords[j];
			                    }
			                }

			                derivedKey.concat(block);
			                blockIndexWords[0]++;
			            }
			            derivedKey.sigBytes = keySize * 4;

			            return derivedKey;
			        }
			    });

			    /**
			     * Computes the Password-Based Key Derivation Function 2.
			     *
			     * @param {WordArray|string} password The password.
			     * @param {WordArray|string} salt A salt.
			     * @param {Object} cfg (Optional) The configuration options to use for this computation.
			     *
			     * @return {WordArray} The derived key.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var key = CryptoJS.PBKDF2(password, salt);
			     *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8 });
			     *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
			     */
			    C.PBKDF2 = function (password, salt, cfg) {
			        return PBKDF2.create(cfg).compute(password, salt);
			    };
			}());


			return CryptoJS.PBKDF2;

		}));
} (pbkdf2));
	return pbkdf2Exports;
}

var evpkdfExports = {};
var evpkdf = {
  get exports(){ return evpkdfExports; },
  set exports(v){ evpkdfExports = v; },
};

var hasRequiredEvpkdf;

function requireEvpkdf () {
	if (hasRequiredEvpkdf) return evpkdfExports;
	hasRequiredEvpkdf = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireSha1(), requireHmac());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var Base = C_lib.Base;
			    var WordArray = C_lib.WordArray;
			    var C_algo = C.algo;
			    var MD5 = C_algo.MD5;

			    /**
			     * This key derivation function is meant to conform with EVP_BytesToKey.
			     * www.openssl.org/docs/crypto/EVP_BytesToKey.html
			     */
			    var EvpKDF = C_algo.EvpKDF = Base.extend({
			        /**
			         * Configuration options.
			         *
			         * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
			         * @property {Hasher} hasher The hash algorithm to use. Default: MD5
			         * @property {number} iterations The number of iterations to perform. Default: 1
			         */
			        cfg: Base.extend({
			            keySize: 128/32,
			            hasher: MD5,
			            iterations: 1
			        }),

			        /**
			         * Initializes a newly created key derivation function.
			         *
			         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
			         *
			         * @example
			         *
			         *     var kdf = CryptoJS.algo.EvpKDF.create();
			         *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8 });
			         *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8, iterations: 1000 });
			         */
			        init: function (cfg) {
			            this.cfg = this.cfg.extend(cfg);
			        },

			        /**
			         * Derives a key from a password.
			         *
			         * @param {WordArray|string} password The password.
			         * @param {WordArray|string} salt A salt.
			         *
			         * @return {WordArray} The derived key.
			         *
			         * @example
			         *
			         *     var key = kdf.compute(password, salt);
			         */
			        compute: function (password, salt) {
			            var block;

			            // Shortcut
			            var cfg = this.cfg;

			            // Init hasher
			            var hasher = cfg.hasher.create();

			            // Initial values
			            var derivedKey = WordArray.create();

			            // Shortcuts
			            var derivedKeyWords = derivedKey.words;
			            var keySize = cfg.keySize;
			            var iterations = cfg.iterations;

			            // Generate key
			            while (derivedKeyWords.length < keySize) {
			                if (block) {
			                    hasher.update(block);
			                }
			                block = hasher.update(password).finalize(salt);
			                hasher.reset();

			                // Iterations
			                for (var i = 1; i < iterations; i++) {
			                    block = hasher.finalize(block);
			                    hasher.reset();
			                }

			                derivedKey.concat(block);
			            }
			            derivedKey.sigBytes = keySize * 4;

			            return derivedKey;
			        }
			    });

			    /**
			     * Derives a key from a password.
			     *
			     * @param {WordArray|string} password The password.
			     * @param {WordArray|string} salt A salt.
			     * @param {Object} cfg (Optional) The configuration options to use for this computation.
			     *
			     * @return {WordArray} The derived key.
			     *
			     * @static
			     *
			     * @example
			     *
			     *     var key = CryptoJS.EvpKDF(password, salt);
			     *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8 });
			     *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8, iterations: 1000 });
			     */
			    C.EvpKDF = function (password, salt, cfg) {
			        return EvpKDF.create(cfg).compute(password, salt);
			    };
			}());


			return CryptoJS.EvpKDF;

		}));
} (evpkdf));
	return evpkdfExports;
}

var cipherCoreExports = {};
var cipherCore = {
  get exports(){ return cipherCoreExports; },
  set exports(v){ cipherCoreExports = v; },
};

var hasRequiredCipherCore;

function requireCipherCore () {
	if (hasRequiredCipherCore) return cipherCoreExports;
	hasRequiredCipherCore = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireEvpkdf());
			}
		}(commonjsGlobal, function (CryptoJS) {

			/**
			 * Cipher core components.
			 */
			CryptoJS.lib.Cipher || (function (undefined$1) {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var Base = C_lib.Base;
			    var WordArray = C_lib.WordArray;
			    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm;
			    var C_enc = C.enc;
			    C_enc.Utf8;
			    var Base64 = C_enc.Base64;
			    var C_algo = C.algo;
			    var EvpKDF = C_algo.EvpKDF;

			    /**
			     * Abstract base cipher template.
			     *
			     * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
			     * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
			     * @property {number} _ENC_XFORM_MODE A constant representing encryption mode.
			     * @property {number} _DEC_XFORM_MODE A constant representing decryption mode.
			     */
			    var Cipher = C_lib.Cipher = BufferedBlockAlgorithm.extend({
			        /**
			         * Configuration options.
			         *
			         * @property {WordArray} iv The IV to use for this operation.
			         */
			        cfg: Base.extend(),

			        /**
			         * Creates this cipher in encryption mode.
			         *
			         * @param {WordArray} key The key.
			         * @param {Object} cfg (Optional) The configuration options to use for this operation.
			         *
			         * @return {Cipher} A cipher instance.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
			         */
			        createEncryptor: function (key, cfg) {
			            return this.create(this._ENC_XFORM_MODE, key, cfg);
			        },

			        /**
			         * Creates this cipher in decryption mode.
			         *
			         * @param {WordArray} key The key.
			         * @param {Object} cfg (Optional) The configuration options to use for this operation.
			         *
			         * @return {Cipher} A cipher instance.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
			         */
			        createDecryptor: function (key, cfg) {
			            return this.create(this._DEC_XFORM_MODE, key, cfg);
			        },

			        /**
			         * Initializes a newly created cipher.
			         *
			         * @param {number} xformMode Either the encryption or decryption transormation mode constant.
			         * @param {WordArray} key The key.
			         * @param {Object} cfg (Optional) The configuration options to use for this operation.
			         *
			         * @example
			         *
			         *     var cipher = CryptoJS.algo.AES.create(CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray });
			         */
			        init: function (xformMode, key, cfg) {
			            // Apply config defaults
			            this.cfg = this.cfg.extend(cfg);

			            // Store transform mode and key
			            this._xformMode = xformMode;
			            this._key = key;

			            // Set initial values
			            this.reset();
			        },

			        /**
			         * Resets this cipher to its initial state.
			         *
			         * @example
			         *
			         *     cipher.reset();
			         */
			        reset: function () {
			            // Reset data buffer
			            BufferedBlockAlgorithm.reset.call(this);

			            // Perform concrete-cipher logic
			            this._doReset();
			        },

			        /**
			         * Adds data to be encrypted or decrypted.
			         *
			         * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
			         *
			         * @return {WordArray} The data after processing.
			         *
			         * @example
			         *
			         *     var encrypted = cipher.process('data');
			         *     var encrypted = cipher.process(wordArray);
			         */
			        process: function (dataUpdate) {
			            // Append
			            this._append(dataUpdate);

			            // Process available blocks
			            return this._process();
			        },

			        /**
			         * Finalizes the encryption or decryption process.
			         * Note that the finalize operation is effectively a destructive, read-once operation.
			         *
			         * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
			         *
			         * @return {WordArray} The data after final processing.
			         *
			         * @example
			         *
			         *     var encrypted = cipher.finalize();
			         *     var encrypted = cipher.finalize('data');
			         *     var encrypted = cipher.finalize(wordArray);
			         */
			        finalize: function (dataUpdate) {
			            // Final data update
			            if (dataUpdate) {
			                this._append(dataUpdate);
			            }

			            // Perform concrete-cipher logic
			            var finalProcessedData = this._doFinalize();

			            return finalProcessedData;
			        },

			        keySize: 128/32,

			        ivSize: 128/32,

			        _ENC_XFORM_MODE: 1,

			        _DEC_XFORM_MODE: 2,

			        /**
			         * Creates shortcut functions to a cipher's object interface.
			         *
			         * @param {Cipher} cipher The cipher to create a helper for.
			         *
			         * @return {Object} An object with encrypt and decrypt shortcut functions.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var AES = CryptoJS.lib.Cipher._createHelper(CryptoJS.algo.AES);
			         */
			        _createHelper: (function () {
			            function selectCipherStrategy(key) {
			                if (typeof key == 'string') {
			                    return PasswordBasedCipher;
			                } else {
			                    return SerializableCipher;
			                }
			            }

			            return function (cipher) {
			                return {
			                    encrypt: function (message, key, cfg) {
			                        return selectCipherStrategy(key).encrypt(cipher, message, key, cfg);
			                    },

			                    decrypt: function (ciphertext, key, cfg) {
			                        return selectCipherStrategy(key).decrypt(cipher, ciphertext, key, cfg);
			                    }
			                };
			            };
			        }())
			    });

			    /**
			     * Abstract base stream cipher template.
			     *
			     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
			     */
			    C_lib.StreamCipher = Cipher.extend({
			        _doFinalize: function () {
			            // Process partial blocks
			            var finalProcessedBlocks = this._process(!!'flush');

			            return finalProcessedBlocks;
			        },

			        blockSize: 1
			    });

			    /**
			     * Mode namespace.
			     */
			    var C_mode = C.mode = {};

			    /**
			     * Abstract base block cipher mode template.
			     */
			    var BlockCipherMode = C_lib.BlockCipherMode = Base.extend({
			        /**
			         * Creates this mode for encryption.
			         *
			         * @param {Cipher} cipher A block cipher instance.
			         * @param {Array} iv The IV words.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var mode = CryptoJS.mode.CBC.createEncryptor(cipher, iv.words);
			         */
			        createEncryptor: function (cipher, iv) {
			            return this.Encryptor.create(cipher, iv);
			        },

			        /**
			         * Creates this mode for decryption.
			         *
			         * @param {Cipher} cipher A block cipher instance.
			         * @param {Array} iv The IV words.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var mode = CryptoJS.mode.CBC.createDecryptor(cipher, iv.words);
			         */
			        createDecryptor: function (cipher, iv) {
			            return this.Decryptor.create(cipher, iv);
			        },

			        /**
			         * Initializes a newly created mode.
			         *
			         * @param {Cipher} cipher A block cipher instance.
			         * @param {Array} iv The IV words.
			         *
			         * @example
			         *
			         *     var mode = CryptoJS.mode.CBC.Encryptor.create(cipher, iv.words);
			         */
			        init: function (cipher, iv) {
			            this._cipher = cipher;
			            this._iv = iv;
			        }
			    });

			    /**
			     * Cipher Block Chaining mode.
			     */
			    var CBC = C_mode.CBC = (function () {
			        /**
			         * Abstract base CBC mode.
			         */
			        var CBC = BlockCipherMode.extend();

			        /**
			         * CBC encryptor.
			         */
			        CBC.Encryptor = CBC.extend({
			            /**
			             * Processes the data block at offset.
			             *
			             * @param {Array} words The data words to operate on.
			             * @param {number} offset The offset where the block starts.
			             *
			             * @example
			             *
			             *     mode.processBlock(data.words, offset);
			             */
			            processBlock: function (words, offset) {
			                // Shortcuts
			                var cipher = this._cipher;
			                var blockSize = cipher.blockSize;

			                // XOR and encrypt
			                xorBlock.call(this, words, offset, blockSize);
			                cipher.encryptBlock(words, offset);

			                // Remember this block to use with next block
			                this._prevBlock = words.slice(offset, offset + blockSize);
			            }
			        });

			        /**
			         * CBC decryptor.
			         */
			        CBC.Decryptor = CBC.extend({
			            /**
			             * Processes the data block at offset.
			             *
			             * @param {Array} words The data words to operate on.
			             * @param {number} offset The offset where the block starts.
			             *
			             * @example
			             *
			             *     mode.processBlock(data.words, offset);
			             */
			            processBlock: function (words, offset) {
			                // Shortcuts
			                var cipher = this._cipher;
			                var blockSize = cipher.blockSize;

			                // Remember this block to use with next block
			                var thisBlock = words.slice(offset, offset + blockSize);

			                // Decrypt and XOR
			                cipher.decryptBlock(words, offset);
			                xorBlock.call(this, words, offset, blockSize);

			                // This block becomes the previous block
			                this._prevBlock = thisBlock;
			            }
			        });

			        function xorBlock(words, offset, blockSize) {
			            var block;

			            // Shortcut
			            var iv = this._iv;

			            // Choose mixing block
			            if (iv) {
			                block = iv;

			                // Remove IV for subsequent blocks
			                this._iv = undefined$1;
			            } else {
			                block = this._prevBlock;
			            }

			            // XOR blocks
			            for (var i = 0; i < blockSize; i++) {
			                words[offset + i] ^= block[i];
			            }
			        }

			        return CBC;
			    }());

			    /**
			     * Padding namespace.
			     */
			    var C_pad = C.pad = {};

			    /**
			     * PKCS #5/7 padding strategy.
			     */
			    var Pkcs7 = C_pad.Pkcs7 = {
			        /**
			         * Pads data using the algorithm defined in PKCS #5/7.
			         *
			         * @param {WordArray} data The data to pad.
			         * @param {number} blockSize The multiple that the data should be padded to.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
			         */
			        pad: function (data, blockSize) {
			            // Shortcut
			            var blockSizeBytes = blockSize * 4;

			            // Count padding bytes
			            var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

			            // Create padding word
			            var paddingWord = (nPaddingBytes << 24) | (nPaddingBytes << 16) | (nPaddingBytes << 8) | nPaddingBytes;

			            // Create padding
			            var paddingWords = [];
			            for (var i = 0; i < nPaddingBytes; i += 4) {
			                paddingWords.push(paddingWord);
			            }
			            var padding = WordArray.create(paddingWords, nPaddingBytes);

			            // Add padding
			            data.concat(padding);
			        },

			        /**
			         * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
			         *
			         * @param {WordArray} data The data to unpad.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     CryptoJS.pad.Pkcs7.unpad(wordArray);
			         */
			        unpad: function (data) {
			            // Get number of padding bytes from last byte
			            var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

			            // Remove padding
			            data.sigBytes -= nPaddingBytes;
			        }
			    };

			    /**
			     * Abstract base block cipher template.
			     *
			     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
			     */
			    C_lib.BlockCipher = Cipher.extend({
			        /**
			         * Configuration options.
			         *
			         * @property {Mode} mode The block mode to use. Default: CBC
			         * @property {Padding} padding The padding strategy to use. Default: Pkcs7
			         */
			        cfg: Cipher.cfg.extend({
			            mode: CBC,
			            padding: Pkcs7
			        }),

			        reset: function () {
			            var modeCreator;

			            // Reset cipher
			            Cipher.reset.call(this);

			            // Shortcuts
			            var cfg = this.cfg;
			            var iv = cfg.iv;
			            var mode = cfg.mode;

			            // Reset block mode
			            if (this._xformMode == this._ENC_XFORM_MODE) {
			                modeCreator = mode.createEncryptor;
			            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
			                modeCreator = mode.createDecryptor;
			                // Keep at least one block in the buffer for unpadding
			                this._minBufferSize = 1;
			            }

			            if (this._mode && this._mode.__creator == modeCreator) {
			                this._mode.init(this, iv && iv.words);
			            } else {
			                this._mode = modeCreator.call(mode, this, iv && iv.words);
			                this._mode.__creator = modeCreator;
			            }
			        },

			        _doProcessBlock: function (words, offset) {
			            this._mode.processBlock(words, offset);
			        },

			        _doFinalize: function () {
			            var finalProcessedBlocks;

			            // Shortcut
			            var padding = this.cfg.padding;

			            // Finalize
			            if (this._xformMode == this._ENC_XFORM_MODE) {
			                // Pad data
			                padding.pad(this._data, this.blockSize);

			                // Process final blocks
			                finalProcessedBlocks = this._process(!!'flush');
			            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
			                // Process final blocks
			                finalProcessedBlocks = this._process(!!'flush');

			                // Unpad data
			                padding.unpad(finalProcessedBlocks);
			            }

			            return finalProcessedBlocks;
			        },

			        blockSize: 128/32
			    });

			    /**
			     * A collection of cipher parameters.
			     *
			     * @property {WordArray} ciphertext The raw ciphertext.
			     * @property {WordArray} key The key to this ciphertext.
			     * @property {WordArray} iv The IV used in the ciphering operation.
			     * @property {WordArray} salt The salt used with a key derivation function.
			     * @property {Cipher} algorithm The cipher algorithm.
			     * @property {Mode} mode The block mode used in the ciphering operation.
			     * @property {Padding} padding The padding scheme used in the ciphering operation.
			     * @property {number} blockSize The block size of the cipher.
			     * @property {Format} formatter The default formatting strategy to convert this cipher params object to a string.
			     */
			    var CipherParams = C_lib.CipherParams = Base.extend({
			        /**
			         * Initializes a newly created cipher params object.
			         *
			         * @param {Object} cipherParams An object with any of the possible cipher parameters.
			         *
			         * @example
			         *
			         *     var cipherParams = CryptoJS.lib.CipherParams.create({
			         *         ciphertext: ciphertextWordArray,
			         *         key: keyWordArray,
			         *         iv: ivWordArray,
			         *         salt: saltWordArray,
			         *         algorithm: CryptoJS.algo.AES,
			         *         mode: CryptoJS.mode.CBC,
			         *         padding: CryptoJS.pad.PKCS7,
			         *         blockSize: 4,
			         *         formatter: CryptoJS.format.OpenSSL
			         *     });
			         */
			        init: function (cipherParams) {
			            this.mixIn(cipherParams);
			        },

			        /**
			         * Converts this cipher params object to a string.
			         *
			         * @param {Format} formatter (Optional) The formatting strategy to use.
			         *
			         * @return {string} The stringified cipher params.
			         *
			         * @throws Error If neither the formatter nor the default formatter is set.
			         *
			         * @example
			         *
			         *     var string = cipherParams + '';
			         *     var string = cipherParams.toString();
			         *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
			         */
			        toString: function (formatter) {
			            return (formatter || this.formatter).stringify(this);
			        }
			    });

			    /**
			     * Format namespace.
			     */
			    var C_format = C.format = {};

			    /**
			     * OpenSSL formatting strategy.
			     */
			    var OpenSSLFormatter = C_format.OpenSSL = {
			        /**
			         * Converts a cipher params object to an OpenSSL-compatible string.
			         *
			         * @param {CipherParams} cipherParams The cipher params object.
			         *
			         * @return {string} The OpenSSL-compatible string.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
			         */
			        stringify: function (cipherParams) {
			            var wordArray;

			            // Shortcuts
			            var ciphertext = cipherParams.ciphertext;
			            var salt = cipherParams.salt;

			            // Format
			            if (salt) {
			                wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
			            } else {
			                wordArray = ciphertext;
			            }

			            return wordArray.toString(Base64);
			        },

			        /**
			         * Converts an OpenSSL-compatible string to a cipher params object.
			         *
			         * @param {string} openSSLStr The OpenSSL-compatible string.
			         *
			         * @return {CipherParams} The cipher params object.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
			         */
			        parse: function (openSSLStr) {
			            var salt;

			            // Parse base64
			            var ciphertext = Base64.parse(openSSLStr);

			            // Shortcut
			            var ciphertextWords = ciphertext.words;

			            // Test for salt
			            if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {
			                // Extract salt
			                salt = WordArray.create(ciphertextWords.slice(2, 4));

			                // Remove salt from ciphertext
			                ciphertextWords.splice(0, 4);
			                ciphertext.sigBytes -= 16;
			            }

			            return CipherParams.create({ ciphertext: ciphertext, salt: salt });
			        }
			    };

			    /**
			     * A cipher wrapper that returns ciphertext as a serializable cipher params object.
			     */
			    var SerializableCipher = C_lib.SerializableCipher = Base.extend({
			        /**
			         * Configuration options.
			         *
			         * @property {Formatter} format The formatting strategy to convert cipher param objects to and from a string. Default: OpenSSL
			         */
			        cfg: Base.extend({
			            format: OpenSSLFormatter
			        }),

			        /**
			         * Encrypts a message.
			         *
			         * @param {Cipher} cipher The cipher algorithm to use.
			         * @param {WordArray|string} message The message to encrypt.
			         * @param {WordArray} key The key.
			         * @param {Object} cfg (Optional) The configuration options to use for this operation.
			         *
			         * @return {CipherParams} A cipher params object.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key);
			         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv });
			         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv, format: CryptoJS.format.OpenSSL });
			         */
			        encrypt: function (cipher, message, key, cfg) {
			            // Apply config defaults
			            cfg = this.cfg.extend(cfg);

			            // Encrypt
			            var encryptor = cipher.createEncryptor(key, cfg);
			            var ciphertext = encryptor.finalize(message);

			            // Shortcut
			            var cipherCfg = encryptor.cfg;

			            // Create and return serializable cipher params
			            return CipherParams.create({
			                ciphertext: ciphertext,
			                key: key,
			                iv: cipherCfg.iv,
			                algorithm: cipher,
			                mode: cipherCfg.mode,
			                padding: cipherCfg.padding,
			                blockSize: cipher.blockSize,
			                formatter: cfg.format
			            });
			        },

			        /**
			         * Decrypts serialized ciphertext.
			         *
			         * @param {Cipher} cipher The cipher algorithm to use.
			         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
			         * @param {WordArray} key The key.
			         * @param {Object} cfg (Optional) The configuration options to use for this operation.
			         *
			         * @return {WordArray} The plaintext.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, key, { iv: iv, format: CryptoJS.format.OpenSSL });
			         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, key, { iv: iv, format: CryptoJS.format.OpenSSL });
			         */
			        decrypt: function (cipher, ciphertext, key, cfg) {
			            // Apply config defaults
			            cfg = this.cfg.extend(cfg);

			            // Convert string to CipherParams
			            ciphertext = this._parse(ciphertext, cfg.format);

			            // Decrypt
			            var plaintext = cipher.createDecryptor(key, cfg).finalize(ciphertext.ciphertext);

			            return plaintext;
			        },

			        /**
			         * Converts serialized ciphertext to CipherParams,
			         * else assumed CipherParams already and returns ciphertext unchanged.
			         *
			         * @param {CipherParams|string} ciphertext The ciphertext.
			         * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
			         *
			         * @return {CipherParams} The unserialized ciphertext.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var ciphertextParams = CryptoJS.lib.SerializableCipher._parse(ciphertextStringOrParams, format);
			         */
			        _parse: function (ciphertext, format) {
			            if (typeof ciphertext == 'string') {
			                return format.parse(ciphertext, this);
			            } else {
			                return ciphertext;
			            }
			        }
			    });

			    /**
			     * Key derivation function namespace.
			     */
			    var C_kdf = C.kdf = {};

			    /**
			     * OpenSSL key derivation function.
			     */
			    var OpenSSLKdf = C_kdf.OpenSSL = {
			        /**
			         * Derives a key and IV from a password.
			         *
			         * @param {string} password The password to derive from.
			         * @param {number} keySize The size in words of the key to generate.
			         * @param {number} ivSize The size in words of the IV to generate.
			         * @param {WordArray|string} salt (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
			         *
			         * @return {CipherParams} A cipher params object with the key, IV, and salt.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32);
			         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32, 'saltsalt');
			         */
			        execute: function (password, keySize, ivSize, salt) {
			            // Generate random salt
			            if (!salt) {
			                salt = WordArray.random(64/8);
			            }

			            // Derive key and IV
			            var key = EvpKDF.create({ keySize: keySize + ivSize }).compute(password, salt);

			            // Separate key and IV
			            var iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
			            key.sigBytes = keySize * 4;

			            // Return params
			            return CipherParams.create({ key: key, iv: iv, salt: salt });
			        }
			    };

			    /**
			     * A serializable cipher wrapper that derives the key from a password,
			     * and returns ciphertext as a serializable cipher params object.
			     */
			    var PasswordBasedCipher = C_lib.PasswordBasedCipher = SerializableCipher.extend({
			        /**
			         * Configuration options.
			         *
			         * @property {KDF} kdf The key derivation function to use to generate a key and IV from a password. Default: OpenSSL
			         */
			        cfg: SerializableCipher.cfg.extend({
			            kdf: OpenSSLKdf
			        }),

			        /**
			         * Encrypts a message using a password.
			         *
			         * @param {Cipher} cipher The cipher algorithm to use.
			         * @param {WordArray|string} message The message to encrypt.
			         * @param {string} password The password.
			         * @param {Object} cfg (Optional) The configuration options to use for this operation.
			         *
			         * @return {CipherParams} A cipher params object.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password');
			         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password', { format: CryptoJS.format.OpenSSL });
			         */
			        encrypt: function (cipher, message, password, cfg) {
			            // Apply config defaults
			            cfg = this.cfg.extend(cfg);

			            // Derive key and other params
			            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize);

			            // Add IV to config
			            cfg.iv = derivedParams.iv;

			            // Encrypt
			            var ciphertext = SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, cfg);

			            // Mix in derived params
			            ciphertext.mixIn(derivedParams);

			            return ciphertext;
			        },

			        /**
			         * Decrypts serialized ciphertext using a password.
			         *
			         * @param {Cipher} cipher The cipher algorithm to use.
			         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
			         * @param {string} password The password.
			         * @param {Object} cfg (Optional) The configuration options to use for this operation.
			         *
			         * @return {WordArray} The plaintext.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, 'password', { format: CryptoJS.format.OpenSSL });
			         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, 'password', { format: CryptoJS.format.OpenSSL });
			         */
			        decrypt: function (cipher, ciphertext, password, cfg) {
			            // Apply config defaults
			            cfg = this.cfg.extend(cfg);

			            // Convert string to CipherParams
			            ciphertext = this._parse(ciphertext, cfg.format);

			            // Derive key and other params
			            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, ciphertext.salt);

			            // Add IV to config
			            cfg.iv = derivedParams.iv;

			            // Decrypt
			            var plaintext = SerializableCipher.decrypt.call(this, cipher, ciphertext, derivedParams.key, cfg);

			            return plaintext;
			        }
			    });
			}());


		}));
} (cipherCore));
	return cipherCoreExports;
}

var modeCfbExports = {};
var modeCfb = {
  get exports(){ return modeCfbExports; },
  set exports(v){ modeCfbExports = v; },
};

var hasRequiredModeCfb;

function requireModeCfb () {
	if (hasRequiredModeCfb) return modeCfbExports;
	hasRequiredModeCfb = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			/**
			 * Cipher Feedback block mode.
			 */
			CryptoJS.mode.CFB = (function () {
			    var CFB = CryptoJS.lib.BlockCipherMode.extend();

			    CFB.Encryptor = CFB.extend({
			        processBlock: function (words, offset) {
			            // Shortcuts
			            var cipher = this._cipher;
			            var blockSize = cipher.blockSize;

			            generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

			            // Remember this block to use with next block
			            this._prevBlock = words.slice(offset, offset + blockSize);
			        }
			    });

			    CFB.Decryptor = CFB.extend({
			        processBlock: function (words, offset) {
			            // Shortcuts
			            var cipher = this._cipher;
			            var blockSize = cipher.blockSize;

			            // Remember this block to use with next block
			            var thisBlock = words.slice(offset, offset + blockSize);

			            generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

			            // This block becomes the previous block
			            this._prevBlock = thisBlock;
			        }
			    });

			    function generateKeystreamAndEncrypt(words, offset, blockSize, cipher) {
			        var keystream;

			        // Shortcut
			        var iv = this._iv;

			        // Generate keystream
			        if (iv) {
			            keystream = iv.slice(0);

			            // Remove IV for subsequent blocks
			            this._iv = undefined;
			        } else {
			            keystream = this._prevBlock;
			        }
			        cipher.encryptBlock(keystream, 0);

			        // Encrypt
			        for (var i = 0; i < blockSize; i++) {
			            words[offset + i] ^= keystream[i];
			        }
			    }

			    return CFB;
			}());


			return CryptoJS.mode.CFB;

		}));
} (modeCfb));
	return modeCfbExports;
}

var modeCtrExports = {};
var modeCtr = {
  get exports(){ return modeCtrExports; },
  set exports(v){ modeCtrExports = v; },
};

var hasRequiredModeCtr;

function requireModeCtr () {
	if (hasRequiredModeCtr) return modeCtrExports;
	hasRequiredModeCtr = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			/**
			 * Counter block mode.
			 */
			CryptoJS.mode.CTR = (function () {
			    var CTR = CryptoJS.lib.BlockCipherMode.extend();

			    var Encryptor = CTR.Encryptor = CTR.extend({
			        processBlock: function (words, offset) {
			            // Shortcuts
			            var cipher = this._cipher;
			            var blockSize = cipher.blockSize;
			            var iv = this._iv;
			            var counter = this._counter;

			            // Generate keystream
			            if (iv) {
			                counter = this._counter = iv.slice(0);

			                // Remove IV for subsequent blocks
			                this._iv = undefined;
			            }
			            var keystream = counter.slice(0);
			            cipher.encryptBlock(keystream, 0);

			            // Increment counter
			            counter[blockSize - 1] = (counter[blockSize - 1] + 1) | 0;

			            // Encrypt
			            for (var i = 0; i < blockSize; i++) {
			                words[offset + i] ^= keystream[i];
			            }
			        }
			    });

			    CTR.Decryptor = Encryptor;

			    return CTR;
			}());


			return CryptoJS.mode.CTR;

		}));
} (modeCtr));
	return modeCtrExports;
}

var modeCtrGladmanExports = {};
var modeCtrGladman = {
  get exports(){ return modeCtrGladmanExports; },
  set exports(v){ modeCtrGladmanExports = v; },
};

var hasRequiredModeCtrGladman;

function requireModeCtrGladman () {
	if (hasRequiredModeCtrGladman) return modeCtrGladmanExports;
	hasRequiredModeCtrGladman = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			/** @preserve
			 * Counter block mode compatible with  Dr Brian Gladman fileenc.c
			 * derived from CryptoJS.mode.CTR
			 * Jan Hruby jhruby.web@gmail.com
			 */
			CryptoJS.mode.CTRGladman = (function () {
			    var CTRGladman = CryptoJS.lib.BlockCipherMode.extend();

				function incWord(word)
				{
					if (((word >> 24) & 0xff) === 0xff) { //overflow
					var b1 = (word >> 16)&0xff;
					var b2 = (word >> 8)&0xff;
					var b3 = word & 0xff;

					if (b1 === 0xff) // overflow b1
					{
					b1 = 0;
					if (b2 === 0xff)
					{
						b2 = 0;
						if (b3 === 0xff)
						{
							b3 = 0;
						}
						else
						{
							++b3;
						}
					}
					else
					{
						++b2;
					}
					}
					else
					{
					++b1;
					}

					word = 0;
					word += (b1 << 16);
					word += (b2 << 8);
					word += b3;
					}
					else
					{
					word += (0x01 << 24);
					}
					return word;
				}

				function incCounter(counter)
				{
					if ((counter[0] = incWord(counter[0])) === 0)
					{
						// encr_data in fileenc.c from  Dr Brian Gladman's counts only with DWORD j < 8
						counter[1] = incWord(counter[1]);
					}
					return counter;
				}

			    var Encryptor = CTRGladman.Encryptor = CTRGladman.extend({
			        processBlock: function (words, offset) {
			            // Shortcuts
			            var cipher = this._cipher;
			            var blockSize = cipher.blockSize;
			            var iv = this._iv;
			            var counter = this._counter;

			            // Generate keystream
			            if (iv) {
			                counter = this._counter = iv.slice(0);

			                // Remove IV for subsequent blocks
			                this._iv = undefined;
			            }

						incCounter(counter);

						var keystream = counter.slice(0);
			            cipher.encryptBlock(keystream, 0);

			            // Encrypt
			            for (var i = 0; i < blockSize; i++) {
			                words[offset + i] ^= keystream[i];
			            }
			        }
			    });

			    CTRGladman.Decryptor = Encryptor;

			    return CTRGladman;
			}());




			return CryptoJS.mode.CTRGladman;

		}));
} (modeCtrGladman));
	return modeCtrGladmanExports;
}

var modeOfbExports = {};
var modeOfb = {
  get exports(){ return modeOfbExports; },
  set exports(v){ modeOfbExports = v; },
};

var hasRequiredModeOfb;

function requireModeOfb () {
	if (hasRequiredModeOfb) return modeOfbExports;
	hasRequiredModeOfb = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			/**
			 * Output Feedback block mode.
			 */
			CryptoJS.mode.OFB = (function () {
			    var OFB = CryptoJS.lib.BlockCipherMode.extend();

			    var Encryptor = OFB.Encryptor = OFB.extend({
			        processBlock: function (words, offset) {
			            // Shortcuts
			            var cipher = this._cipher;
			            var blockSize = cipher.blockSize;
			            var iv = this._iv;
			            var keystream = this._keystream;

			            // Generate keystream
			            if (iv) {
			                keystream = this._keystream = iv.slice(0);

			                // Remove IV for subsequent blocks
			                this._iv = undefined;
			            }
			            cipher.encryptBlock(keystream, 0);

			            // Encrypt
			            for (var i = 0; i < blockSize; i++) {
			                words[offset + i] ^= keystream[i];
			            }
			        }
			    });

			    OFB.Decryptor = Encryptor;

			    return OFB;
			}());


			return CryptoJS.mode.OFB;

		}));
} (modeOfb));
	return modeOfbExports;
}

var modeEcbExports = {};
var modeEcb = {
  get exports(){ return modeEcbExports; },
  set exports(v){ modeEcbExports = v; },
};

var hasRequiredModeEcb;

function requireModeEcb () {
	if (hasRequiredModeEcb) return modeEcbExports;
	hasRequiredModeEcb = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			/**
			 * Electronic Codebook block mode.
			 */
			CryptoJS.mode.ECB = (function () {
			    var ECB = CryptoJS.lib.BlockCipherMode.extend();

			    ECB.Encryptor = ECB.extend({
			        processBlock: function (words, offset) {
			            this._cipher.encryptBlock(words, offset);
			        }
			    });

			    ECB.Decryptor = ECB.extend({
			        processBlock: function (words, offset) {
			            this._cipher.decryptBlock(words, offset);
			        }
			    });

			    return ECB;
			}());


			return CryptoJS.mode.ECB;

		}));
} (modeEcb));
	return modeEcbExports;
}

var padAnsix923Exports = {};
var padAnsix923 = {
  get exports(){ return padAnsix923Exports; },
  set exports(v){ padAnsix923Exports = v; },
};

var hasRequiredPadAnsix923;

function requirePadAnsix923 () {
	if (hasRequiredPadAnsix923) return padAnsix923Exports;
	hasRequiredPadAnsix923 = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			/**
			 * ANSI X.923 padding strategy.
			 */
			CryptoJS.pad.AnsiX923 = {
			    pad: function (data, blockSize) {
			        // Shortcuts
			        var dataSigBytes = data.sigBytes;
			        var blockSizeBytes = blockSize * 4;

			        // Count padding bytes
			        var nPaddingBytes = blockSizeBytes - dataSigBytes % blockSizeBytes;

			        // Compute last byte position
			        var lastBytePos = dataSigBytes + nPaddingBytes - 1;

			        // Pad
			        data.clamp();
			        data.words[lastBytePos >>> 2] |= nPaddingBytes << (24 - (lastBytePos % 4) * 8);
			        data.sigBytes += nPaddingBytes;
			    },

			    unpad: function (data) {
			        // Get number of padding bytes from last byte
			        var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

			        // Remove padding
			        data.sigBytes -= nPaddingBytes;
			    }
			};


			return CryptoJS.pad.Ansix923;

		}));
} (padAnsix923));
	return padAnsix923Exports;
}

var padIso10126Exports = {};
var padIso10126 = {
  get exports(){ return padIso10126Exports; },
  set exports(v){ padIso10126Exports = v; },
};

var hasRequiredPadIso10126;

function requirePadIso10126 () {
	if (hasRequiredPadIso10126) return padIso10126Exports;
	hasRequiredPadIso10126 = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			/**
			 * ISO 10126 padding strategy.
			 */
			CryptoJS.pad.Iso10126 = {
			    pad: function (data, blockSize) {
			        // Shortcut
			        var blockSizeBytes = blockSize * 4;

			        // Count padding bytes
			        var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

			        // Pad
			        data.concat(CryptoJS.lib.WordArray.random(nPaddingBytes - 1)).
			             concat(CryptoJS.lib.WordArray.create([nPaddingBytes << 24], 1));
			    },

			    unpad: function (data) {
			        // Get number of padding bytes from last byte
			        var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

			        // Remove padding
			        data.sigBytes -= nPaddingBytes;
			    }
			};


			return CryptoJS.pad.Iso10126;

		}));
} (padIso10126));
	return padIso10126Exports;
}

var padIso97971Exports = {};
var padIso97971 = {
  get exports(){ return padIso97971Exports; },
  set exports(v){ padIso97971Exports = v; },
};

var hasRequiredPadIso97971;

function requirePadIso97971 () {
	if (hasRequiredPadIso97971) return padIso97971Exports;
	hasRequiredPadIso97971 = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			/**
			 * ISO/IEC 9797-1 Padding Method 2.
			 */
			CryptoJS.pad.Iso97971 = {
			    pad: function (data, blockSize) {
			        // Add 0x80 byte
			        data.concat(CryptoJS.lib.WordArray.create([0x80000000], 1));

			        // Zero pad the rest
			        CryptoJS.pad.ZeroPadding.pad(data, blockSize);
			    },

			    unpad: function (data) {
			        // Remove zero padding
			        CryptoJS.pad.ZeroPadding.unpad(data);

			        // Remove one more byte -- the 0x80 byte
			        data.sigBytes--;
			    }
			};


			return CryptoJS.pad.Iso97971;

		}));
} (padIso97971));
	return padIso97971Exports;
}

var padZeropaddingExports = {};
var padZeropadding = {
  get exports(){ return padZeropaddingExports; },
  set exports(v){ padZeropaddingExports = v; },
};

var hasRequiredPadZeropadding;

function requirePadZeropadding () {
	if (hasRequiredPadZeropadding) return padZeropaddingExports;
	hasRequiredPadZeropadding = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			/**
			 * Zero padding strategy.
			 */
			CryptoJS.pad.ZeroPadding = {
			    pad: function (data, blockSize) {
			        // Shortcut
			        var blockSizeBytes = blockSize * 4;

			        // Pad
			        data.clamp();
			        data.sigBytes += blockSizeBytes - ((data.sigBytes % blockSizeBytes) || blockSizeBytes);
			    },

			    unpad: function (data) {
			        // Shortcut
			        var dataWords = data.words;

			        // Unpad
			        var i = data.sigBytes - 1;
			        for (var i = data.sigBytes - 1; i >= 0; i--) {
			            if (((dataWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff)) {
			                data.sigBytes = i + 1;
			                break;
			            }
			        }
			    }
			};


			return CryptoJS.pad.ZeroPadding;

		}));
} (padZeropadding));
	return padZeropaddingExports;
}

var padNopaddingExports = {};
var padNopadding = {
  get exports(){ return padNopaddingExports; },
  set exports(v){ padNopaddingExports = v; },
};

var hasRequiredPadNopadding;

function requirePadNopadding () {
	if (hasRequiredPadNopadding) return padNopaddingExports;
	hasRequiredPadNopadding = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			/**
			 * A noop padding strategy.
			 */
			CryptoJS.pad.NoPadding = {
			    pad: function () {
			    },

			    unpad: function () {
			    }
			};


			return CryptoJS.pad.NoPadding;

		}));
} (padNopadding));
	return padNopaddingExports;
}

var formatHexExports = {};
var formatHex = {
  get exports(){ return formatHexExports; },
  set exports(v){ formatHexExports = v; },
};

var hasRequiredFormatHex;

function requireFormatHex () {
	if (hasRequiredFormatHex) return formatHexExports;
	hasRequiredFormatHex = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function (undefined$1) {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var CipherParams = C_lib.CipherParams;
			    var C_enc = C.enc;
			    var Hex = C_enc.Hex;
			    var C_format = C.format;

			    C_format.Hex = {
			        /**
			         * Converts the ciphertext of a cipher params object to a hexadecimally encoded string.
			         *
			         * @param {CipherParams} cipherParams The cipher params object.
			         *
			         * @return {string} The hexadecimally encoded string.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var hexString = CryptoJS.format.Hex.stringify(cipherParams);
			         */
			        stringify: function (cipherParams) {
			            return cipherParams.ciphertext.toString(Hex);
			        },

			        /**
			         * Converts a hexadecimally encoded ciphertext string to a cipher params object.
			         *
			         * @param {string} input The hexadecimally encoded string.
			         *
			         * @return {CipherParams} The cipher params object.
			         *
			         * @static
			         *
			         * @example
			         *
			         *     var cipherParams = CryptoJS.format.Hex.parse(hexString);
			         */
			        parse: function (input) {
			            var ciphertext = Hex.parse(input);
			            return CipherParams.create({ ciphertext: ciphertext });
			        }
			    };
			}());


			return CryptoJS.format.Hex;

		}));
} (formatHex));
	return formatHexExports;
}

var aesExports = {};
var aes = {
  get exports(){ return aesExports; },
  set exports(v){ aesExports = v; },
};

var hasRequiredAes;

function requireAes () {
	if (hasRequiredAes) return aesExports;
	hasRequiredAes = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireEncBase64(), requireMd5(), requireEvpkdf(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var BlockCipher = C_lib.BlockCipher;
			    var C_algo = C.algo;

			    // Lookup tables
			    var SBOX = [];
			    var INV_SBOX = [];
			    var SUB_MIX_0 = [];
			    var SUB_MIX_1 = [];
			    var SUB_MIX_2 = [];
			    var SUB_MIX_3 = [];
			    var INV_SUB_MIX_0 = [];
			    var INV_SUB_MIX_1 = [];
			    var INV_SUB_MIX_2 = [];
			    var INV_SUB_MIX_3 = [];

			    // Compute lookup tables
			    (function () {
			        // Compute double table
			        var d = [];
			        for (var i = 0; i < 256; i++) {
			            if (i < 128) {
			                d[i] = i << 1;
			            } else {
			                d[i] = (i << 1) ^ 0x11b;
			            }
			        }

			        // Walk GF(2^8)
			        var x = 0;
			        var xi = 0;
			        for (var i = 0; i < 256; i++) {
			            // Compute sbox
			            var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
			            sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
			            SBOX[x] = sx;
			            INV_SBOX[sx] = x;

			            // Compute multiplication
			            var x2 = d[x];
			            var x4 = d[x2];
			            var x8 = d[x4];

			            // Compute sub bytes, mix columns tables
			            var t = (d[sx] * 0x101) ^ (sx * 0x1010100);
			            SUB_MIX_0[x] = (t << 24) | (t >>> 8);
			            SUB_MIX_1[x] = (t << 16) | (t >>> 16);
			            SUB_MIX_2[x] = (t << 8)  | (t >>> 24);
			            SUB_MIX_3[x] = t;

			            // Compute inv sub bytes, inv mix columns tables
			            var t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
			            INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8);
			            INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16);
			            INV_SUB_MIX_2[sx] = (t << 8)  | (t >>> 24);
			            INV_SUB_MIX_3[sx] = t;

			            // Compute next counter
			            if (!x) {
			                x = xi = 1;
			            } else {
			                x = x2 ^ d[d[d[x8 ^ x2]]];
			                xi ^= d[d[xi]];
			            }
			        }
			    }());

			    // Precomputed Rcon lookup
			    var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

			    /**
			     * AES block cipher algorithm.
			     */
			    var AES = C_algo.AES = BlockCipher.extend({
			        _doReset: function () {
			            var t;

			            // Skip reset of nRounds has been set before and key did not change
			            if (this._nRounds && this._keyPriorReset === this._key) {
			                return;
			            }

			            // Shortcuts
			            var key = this._keyPriorReset = this._key;
			            var keyWords = key.words;
			            var keySize = key.sigBytes / 4;

			            // Compute number of rounds
			            var nRounds = this._nRounds = keySize + 6;

			            // Compute number of key schedule rows
			            var ksRows = (nRounds + 1) * 4;

			            // Compute key schedule
			            var keySchedule = this._keySchedule = [];
			            for (var ksRow = 0; ksRow < ksRows; ksRow++) {
			                if (ksRow < keySize) {
			                    keySchedule[ksRow] = keyWords[ksRow];
			                } else {
			                    t = keySchedule[ksRow - 1];

			                    if (!(ksRow % keySize)) {
			                        // Rot word
			                        t = (t << 8) | (t >>> 24);

			                        // Sub word
			                        t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];

			                        // Mix Rcon
			                        t ^= RCON[(ksRow / keySize) | 0] << 24;
			                    } else if (keySize > 6 && ksRow % keySize == 4) {
			                        // Sub word
			                        t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
			                    }

			                    keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
			                }
			            }

			            // Compute inv key schedule
			            var invKeySchedule = this._invKeySchedule = [];
			            for (var invKsRow = 0; invKsRow < ksRows; invKsRow++) {
			                var ksRow = ksRows - invKsRow;

			                if (invKsRow % 4) {
			                    var t = keySchedule[ksRow];
			                } else {
			                    var t = keySchedule[ksRow - 4];
			                }

			                if (invKsRow < 4 || ksRow <= 4) {
			                    invKeySchedule[invKsRow] = t;
			                } else {
			                    invKeySchedule[invKsRow] = INV_SUB_MIX_0[SBOX[t >>> 24]] ^ INV_SUB_MIX_1[SBOX[(t >>> 16) & 0xff]] ^
			                                               INV_SUB_MIX_2[SBOX[(t >>> 8) & 0xff]] ^ INV_SUB_MIX_3[SBOX[t & 0xff]];
			                }
			            }
			        },

			        encryptBlock: function (M, offset) {
			            this._doCryptBlock(M, offset, this._keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX);
			        },

			        decryptBlock: function (M, offset) {
			            // Swap 2nd and 4th rows
			            var t = M[offset + 1];
			            M[offset + 1] = M[offset + 3];
			            M[offset + 3] = t;

			            this._doCryptBlock(M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

			            // Inv swap 2nd and 4th rows
			            var t = M[offset + 1];
			            M[offset + 1] = M[offset + 3];
			            M[offset + 3] = t;
			        },

			        _doCryptBlock: function (M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
			            // Shortcut
			            var nRounds = this._nRounds;

			            // Get input, add round key
			            var s0 = M[offset]     ^ keySchedule[0];
			            var s1 = M[offset + 1] ^ keySchedule[1];
			            var s2 = M[offset + 2] ^ keySchedule[2];
			            var s3 = M[offset + 3] ^ keySchedule[3];

			            // Key schedule row counter
			            var ksRow = 4;

			            // Rounds
			            for (var round = 1; round < nRounds; round++) {
			                // Shift rows, sub bytes, mix columns, add round key
			                var t0 = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[(s1 >>> 16) & 0xff] ^ SUB_MIX_2[(s2 >>> 8) & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow++];
			                var t1 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[(s2 >>> 16) & 0xff] ^ SUB_MIX_2[(s3 >>> 8) & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow++];
			                var t2 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[(s3 >>> 16) & 0xff] ^ SUB_MIX_2[(s0 >>> 8) & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow++];
			                var t3 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[(s0 >>> 16) & 0xff] ^ SUB_MIX_2[(s1 >>> 8) & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow++];

			                // Update state
			                s0 = t0;
			                s1 = t1;
			                s2 = t2;
			                s3 = t3;
			            }

			            // Shift rows, sub bytes, add round key
			            var t0 = ((SBOX[s0 >>> 24] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) | (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ keySchedule[ksRow++];
			            var t1 = ((SBOX[s1 >>> 24] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) | (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ keySchedule[ksRow++];
			            var t2 = ((SBOX[s2 >>> 24] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) | (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ keySchedule[ksRow++];
			            var t3 = ((SBOX[s3 >>> 24] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) | (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ keySchedule[ksRow++];

			            // Set output
			            M[offset]     = t0;
			            M[offset + 1] = t1;
			            M[offset + 2] = t2;
			            M[offset + 3] = t3;
			        },

			        keySize: 256/32
			    });

			    /**
			     * Shortcut functions to the cipher's object interface.
			     *
			     * @example
			     *
			     *     var ciphertext = CryptoJS.AES.encrypt(message, key, cfg);
			     *     var plaintext  = CryptoJS.AES.decrypt(ciphertext, key, cfg);
			     */
			    C.AES = BlockCipher._createHelper(AES);
			}());


			return CryptoJS.AES;

		}));
} (aes));
	return aesExports;
}

var tripledesExports = {};
var tripledes = {
  get exports(){ return tripledesExports; },
  set exports(v){ tripledesExports = v; },
};

var hasRequiredTripledes;

function requireTripledes () {
	if (hasRequiredTripledes) return tripledesExports;
	hasRequiredTripledes = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireEncBase64(), requireMd5(), requireEvpkdf(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var WordArray = C_lib.WordArray;
			    var BlockCipher = C_lib.BlockCipher;
			    var C_algo = C.algo;

			    // Permuted Choice 1 constants
			    var PC1 = [
			        57, 49, 41, 33, 25, 17, 9,  1,
			        58, 50, 42, 34, 26, 18, 10, 2,
			        59, 51, 43, 35, 27, 19, 11, 3,
			        60, 52, 44, 36, 63, 55, 47, 39,
			        31, 23, 15, 7,  62, 54, 46, 38,
			        30, 22, 14, 6,  61, 53, 45, 37,
			        29, 21, 13, 5,  28, 20, 12, 4
			    ];

			    // Permuted Choice 2 constants
			    var PC2 = [
			        14, 17, 11, 24, 1,  5,
			        3,  28, 15, 6,  21, 10,
			        23, 19, 12, 4,  26, 8,
			        16, 7,  27, 20, 13, 2,
			        41, 52, 31, 37, 47, 55,
			        30, 40, 51, 45, 33, 48,
			        44, 49, 39, 56, 34, 53,
			        46, 42, 50, 36, 29, 32
			    ];

			    // Cumulative bit shift constants
			    var BIT_SHIFTS = [1,  2,  4,  6,  8,  10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

			    // SBOXes and round permutation constants
			    var SBOX_P = [
			        {
			            0x0: 0x808200,
			            0x10000000: 0x8000,
			            0x20000000: 0x808002,
			            0x30000000: 0x2,
			            0x40000000: 0x200,
			            0x50000000: 0x808202,
			            0x60000000: 0x800202,
			            0x70000000: 0x800000,
			            0x80000000: 0x202,
			            0x90000000: 0x800200,
			            0xa0000000: 0x8200,
			            0xb0000000: 0x808000,
			            0xc0000000: 0x8002,
			            0xd0000000: 0x800002,
			            0xe0000000: 0x0,
			            0xf0000000: 0x8202,
			            0x8000000: 0x0,
			            0x18000000: 0x808202,
			            0x28000000: 0x8202,
			            0x38000000: 0x8000,
			            0x48000000: 0x808200,
			            0x58000000: 0x200,
			            0x68000000: 0x808002,
			            0x78000000: 0x2,
			            0x88000000: 0x800200,
			            0x98000000: 0x8200,
			            0xa8000000: 0x808000,
			            0xb8000000: 0x800202,
			            0xc8000000: 0x800002,
			            0xd8000000: 0x8002,
			            0xe8000000: 0x202,
			            0xf8000000: 0x800000,
			            0x1: 0x8000,
			            0x10000001: 0x2,
			            0x20000001: 0x808200,
			            0x30000001: 0x800000,
			            0x40000001: 0x808002,
			            0x50000001: 0x8200,
			            0x60000001: 0x200,
			            0x70000001: 0x800202,
			            0x80000001: 0x808202,
			            0x90000001: 0x808000,
			            0xa0000001: 0x800002,
			            0xb0000001: 0x8202,
			            0xc0000001: 0x202,
			            0xd0000001: 0x800200,
			            0xe0000001: 0x8002,
			            0xf0000001: 0x0,
			            0x8000001: 0x808202,
			            0x18000001: 0x808000,
			            0x28000001: 0x800000,
			            0x38000001: 0x200,
			            0x48000001: 0x8000,
			            0x58000001: 0x800002,
			            0x68000001: 0x2,
			            0x78000001: 0x8202,
			            0x88000001: 0x8002,
			            0x98000001: 0x800202,
			            0xa8000001: 0x202,
			            0xb8000001: 0x808200,
			            0xc8000001: 0x800200,
			            0xd8000001: 0x0,
			            0xe8000001: 0x8200,
			            0xf8000001: 0x808002
			        },
			        {
			            0x0: 0x40084010,
			            0x1000000: 0x4000,
			            0x2000000: 0x80000,
			            0x3000000: 0x40080010,
			            0x4000000: 0x40000010,
			            0x5000000: 0x40084000,
			            0x6000000: 0x40004000,
			            0x7000000: 0x10,
			            0x8000000: 0x84000,
			            0x9000000: 0x40004010,
			            0xa000000: 0x40000000,
			            0xb000000: 0x84010,
			            0xc000000: 0x80010,
			            0xd000000: 0x0,
			            0xe000000: 0x4010,
			            0xf000000: 0x40080000,
			            0x800000: 0x40004000,
			            0x1800000: 0x84010,
			            0x2800000: 0x10,
			            0x3800000: 0x40004010,
			            0x4800000: 0x40084010,
			            0x5800000: 0x40000000,
			            0x6800000: 0x80000,
			            0x7800000: 0x40080010,
			            0x8800000: 0x80010,
			            0x9800000: 0x0,
			            0xa800000: 0x4000,
			            0xb800000: 0x40080000,
			            0xc800000: 0x40000010,
			            0xd800000: 0x84000,
			            0xe800000: 0x40084000,
			            0xf800000: 0x4010,
			            0x10000000: 0x0,
			            0x11000000: 0x40080010,
			            0x12000000: 0x40004010,
			            0x13000000: 0x40084000,
			            0x14000000: 0x40080000,
			            0x15000000: 0x10,
			            0x16000000: 0x84010,
			            0x17000000: 0x4000,
			            0x18000000: 0x4010,
			            0x19000000: 0x80000,
			            0x1a000000: 0x80010,
			            0x1b000000: 0x40000010,
			            0x1c000000: 0x84000,
			            0x1d000000: 0x40004000,
			            0x1e000000: 0x40000000,
			            0x1f000000: 0x40084010,
			            0x10800000: 0x84010,
			            0x11800000: 0x80000,
			            0x12800000: 0x40080000,
			            0x13800000: 0x4000,
			            0x14800000: 0x40004000,
			            0x15800000: 0x40084010,
			            0x16800000: 0x10,
			            0x17800000: 0x40000000,
			            0x18800000: 0x40084000,
			            0x19800000: 0x40000010,
			            0x1a800000: 0x40004010,
			            0x1b800000: 0x80010,
			            0x1c800000: 0x0,
			            0x1d800000: 0x4010,
			            0x1e800000: 0x40080010,
			            0x1f800000: 0x84000
			        },
			        {
			            0x0: 0x104,
			            0x100000: 0x0,
			            0x200000: 0x4000100,
			            0x300000: 0x10104,
			            0x400000: 0x10004,
			            0x500000: 0x4000004,
			            0x600000: 0x4010104,
			            0x700000: 0x4010000,
			            0x800000: 0x4000000,
			            0x900000: 0x4010100,
			            0xa00000: 0x10100,
			            0xb00000: 0x4010004,
			            0xc00000: 0x4000104,
			            0xd00000: 0x10000,
			            0xe00000: 0x4,
			            0xf00000: 0x100,
			            0x80000: 0x4010100,
			            0x180000: 0x4010004,
			            0x280000: 0x0,
			            0x380000: 0x4000100,
			            0x480000: 0x4000004,
			            0x580000: 0x10000,
			            0x680000: 0x10004,
			            0x780000: 0x104,
			            0x880000: 0x4,
			            0x980000: 0x100,
			            0xa80000: 0x4010000,
			            0xb80000: 0x10104,
			            0xc80000: 0x10100,
			            0xd80000: 0x4000104,
			            0xe80000: 0x4010104,
			            0xf80000: 0x4000000,
			            0x1000000: 0x4010100,
			            0x1100000: 0x10004,
			            0x1200000: 0x10000,
			            0x1300000: 0x4000100,
			            0x1400000: 0x100,
			            0x1500000: 0x4010104,
			            0x1600000: 0x4000004,
			            0x1700000: 0x0,
			            0x1800000: 0x4000104,
			            0x1900000: 0x4000000,
			            0x1a00000: 0x4,
			            0x1b00000: 0x10100,
			            0x1c00000: 0x4010000,
			            0x1d00000: 0x104,
			            0x1e00000: 0x10104,
			            0x1f00000: 0x4010004,
			            0x1080000: 0x4000000,
			            0x1180000: 0x104,
			            0x1280000: 0x4010100,
			            0x1380000: 0x0,
			            0x1480000: 0x10004,
			            0x1580000: 0x4000100,
			            0x1680000: 0x100,
			            0x1780000: 0x4010004,
			            0x1880000: 0x10000,
			            0x1980000: 0x4010104,
			            0x1a80000: 0x10104,
			            0x1b80000: 0x4000004,
			            0x1c80000: 0x4000104,
			            0x1d80000: 0x4010000,
			            0x1e80000: 0x4,
			            0x1f80000: 0x10100
			        },
			        {
			            0x0: 0x80401000,
			            0x10000: 0x80001040,
			            0x20000: 0x401040,
			            0x30000: 0x80400000,
			            0x40000: 0x0,
			            0x50000: 0x401000,
			            0x60000: 0x80000040,
			            0x70000: 0x400040,
			            0x80000: 0x80000000,
			            0x90000: 0x400000,
			            0xa0000: 0x40,
			            0xb0000: 0x80001000,
			            0xc0000: 0x80400040,
			            0xd0000: 0x1040,
			            0xe0000: 0x1000,
			            0xf0000: 0x80401040,
			            0x8000: 0x80001040,
			            0x18000: 0x40,
			            0x28000: 0x80400040,
			            0x38000: 0x80001000,
			            0x48000: 0x401000,
			            0x58000: 0x80401040,
			            0x68000: 0x0,
			            0x78000: 0x80400000,
			            0x88000: 0x1000,
			            0x98000: 0x80401000,
			            0xa8000: 0x400000,
			            0xb8000: 0x1040,
			            0xc8000: 0x80000000,
			            0xd8000: 0x400040,
			            0xe8000: 0x401040,
			            0xf8000: 0x80000040,
			            0x100000: 0x400040,
			            0x110000: 0x401000,
			            0x120000: 0x80000040,
			            0x130000: 0x0,
			            0x140000: 0x1040,
			            0x150000: 0x80400040,
			            0x160000: 0x80401000,
			            0x170000: 0x80001040,
			            0x180000: 0x80401040,
			            0x190000: 0x80000000,
			            0x1a0000: 0x80400000,
			            0x1b0000: 0x401040,
			            0x1c0000: 0x80001000,
			            0x1d0000: 0x400000,
			            0x1e0000: 0x40,
			            0x1f0000: 0x1000,
			            0x108000: 0x80400000,
			            0x118000: 0x80401040,
			            0x128000: 0x0,
			            0x138000: 0x401000,
			            0x148000: 0x400040,
			            0x158000: 0x80000000,
			            0x168000: 0x80001040,
			            0x178000: 0x40,
			            0x188000: 0x80000040,
			            0x198000: 0x1000,
			            0x1a8000: 0x80001000,
			            0x1b8000: 0x80400040,
			            0x1c8000: 0x1040,
			            0x1d8000: 0x80401000,
			            0x1e8000: 0x400000,
			            0x1f8000: 0x401040
			        },
			        {
			            0x0: 0x80,
			            0x1000: 0x1040000,
			            0x2000: 0x40000,
			            0x3000: 0x20000000,
			            0x4000: 0x20040080,
			            0x5000: 0x1000080,
			            0x6000: 0x21000080,
			            0x7000: 0x40080,
			            0x8000: 0x1000000,
			            0x9000: 0x20040000,
			            0xa000: 0x20000080,
			            0xb000: 0x21040080,
			            0xc000: 0x21040000,
			            0xd000: 0x0,
			            0xe000: 0x1040080,
			            0xf000: 0x21000000,
			            0x800: 0x1040080,
			            0x1800: 0x21000080,
			            0x2800: 0x80,
			            0x3800: 0x1040000,
			            0x4800: 0x40000,
			            0x5800: 0x20040080,
			            0x6800: 0x21040000,
			            0x7800: 0x20000000,
			            0x8800: 0x20040000,
			            0x9800: 0x0,
			            0xa800: 0x21040080,
			            0xb800: 0x1000080,
			            0xc800: 0x20000080,
			            0xd800: 0x21000000,
			            0xe800: 0x1000000,
			            0xf800: 0x40080,
			            0x10000: 0x40000,
			            0x11000: 0x80,
			            0x12000: 0x20000000,
			            0x13000: 0x21000080,
			            0x14000: 0x1000080,
			            0x15000: 0x21040000,
			            0x16000: 0x20040080,
			            0x17000: 0x1000000,
			            0x18000: 0x21040080,
			            0x19000: 0x21000000,
			            0x1a000: 0x1040000,
			            0x1b000: 0x20040000,
			            0x1c000: 0x40080,
			            0x1d000: 0x20000080,
			            0x1e000: 0x0,
			            0x1f000: 0x1040080,
			            0x10800: 0x21000080,
			            0x11800: 0x1000000,
			            0x12800: 0x1040000,
			            0x13800: 0x20040080,
			            0x14800: 0x20000000,
			            0x15800: 0x1040080,
			            0x16800: 0x80,
			            0x17800: 0x21040000,
			            0x18800: 0x40080,
			            0x19800: 0x21040080,
			            0x1a800: 0x0,
			            0x1b800: 0x21000000,
			            0x1c800: 0x1000080,
			            0x1d800: 0x40000,
			            0x1e800: 0x20040000,
			            0x1f800: 0x20000080
			        },
			        {
			            0x0: 0x10000008,
			            0x100: 0x2000,
			            0x200: 0x10200000,
			            0x300: 0x10202008,
			            0x400: 0x10002000,
			            0x500: 0x200000,
			            0x600: 0x200008,
			            0x700: 0x10000000,
			            0x800: 0x0,
			            0x900: 0x10002008,
			            0xa00: 0x202000,
			            0xb00: 0x8,
			            0xc00: 0x10200008,
			            0xd00: 0x202008,
			            0xe00: 0x2008,
			            0xf00: 0x10202000,
			            0x80: 0x10200000,
			            0x180: 0x10202008,
			            0x280: 0x8,
			            0x380: 0x200000,
			            0x480: 0x202008,
			            0x580: 0x10000008,
			            0x680: 0x10002000,
			            0x780: 0x2008,
			            0x880: 0x200008,
			            0x980: 0x2000,
			            0xa80: 0x10002008,
			            0xb80: 0x10200008,
			            0xc80: 0x0,
			            0xd80: 0x10202000,
			            0xe80: 0x202000,
			            0xf80: 0x10000000,
			            0x1000: 0x10002000,
			            0x1100: 0x10200008,
			            0x1200: 0x10202008,
			            0x1300: 0x2008,
			            0x1400: 0x200000,
			            0x1500: 0x10000000,
			            0x1600: 0x10000008,
			            0x1700: 0x202000,
			            0x1800: 0x202008,
			            0x1900: 0x0,
			            0x1a00: 0x8,
			            0x1b00: 0x10200000,
			            0x1c00: 0x2000,
			            0x1d00: 0x10002008,
			            0x1e00: 0x10202000,
			            0x1f00: 0x200008,
			            0x1080: 0x8,
			            0x1180: 0x202000,
			            0x1280: 0x200000,
			            0x1380: 0x10000008,
			            0x1480: 0x10002000,
			            0x1580: 0x2008,
			            0x1680: 0x10202008,
			            0x1780: 0x10200000,
			            0x1880: 0x10202000,
			            0x1980: 0x10200008,
			            0x1a80: 0x2000,
			            0x1b80: 0x202008,
			            0x1c80: 0x200008,
			            0x1d80: 0x0,
			            0x1e80: 0x10000000,
			            0x1f80: 0x10002008
			        },
			        {
			            0x0: 0x100000,
			            0x10: 0x2000401,
			            0x20: 0x400,
			            0x30: 0x100401,
			            0x40: 0x2100401,
			            0x50: 0x0,
			            0x60: 0x1,
			            0x70: 0x2100001,
			            0x80: 0x2000400,
			            0x90: 0x100001,
			            0xa0: 0x2000001,
			            0xb0: 0x2100400,
			            0xc0: 0x2100000,
			            0xd0: 0x401,
			            0xe0: 0x100400,
			            0xf0: 0x2000000,
			            0x8: 0x2100001,
			            0x18: 0x0,
			            0x28: 0x2000401,
			            0x38: 0x2100400,
			            0x48: 0x100000,
			            0x58: 0x2000001,
			            0x68: 0x2000000,
			            0x78: 0x401,
			            0x88: 0x100401,
			            0x98: 0x2000400,
			            0xa8: 0x2100000,
			            0xb8: 0x100001,
			            0xc8: 0x400,
			            0xd8: 0x2100401,
			            0xe8: 0x1,
			            0xf8: 0x100400,
			            0x100: 0x2000000,
			            0x110: 0x100000,
			            0x120: 0x2000401,
			            0x130: 0x2100001,
			            0x140: 0x100001,
			            0x150: 0x2000400,
			            0x160: 0x2100400,
			            0x170: 0x100401,
			            0x180: 0x401,
			            0x190: 0x2100401,
			            0x1a0: 0x100400,
			            0x1b0: 0x1,
			            0x1c0: 0x0,
			            0x1d0: 0x2100000,
			            0x1e0: 0x2000001,
			            0x1f0: 0x400,
			            0x108: 0x100400,
			            0x118: 0x2000401,
			            0x128: 0x2100001,
			            0x138: 0x1,
			            0x148: 0x2000000,
			            0x158: 0x100000,
			            0x168: 0x401,
			            0x178: 0x2100400,
			            0x188: 0x2000001,
			            0x198: 0x2100000,
			            0x1a8: 0x0,
			            0x1b8: 0x2100401,
			            0x1c8: 0x100401,
			            0x1d8: 0x400,
			            0x1e8: 0x2000400,
			            0x1f8: 0x100001
			        },
			        {
			            0x0: 0x8000820,
			            0x1: 0x20000,
			            0x2: 0x8000000,
			            0x3: 0x20,
			            0x4: 0x20020,
			            0x5: 0x8020820,
			            0x6: 0x8020800,
			            0x7: 0x800,
			            0x8: 0x8020000,
			            0x9: 0x8000800,
			            0xa: 0x20800,
			            0xb: 0x8020020,
			            0xc: 0x820,
			            0xd: 0x0,
			            0xe: 0x8000020,
			            0xf: 0x20820,
			            0x80000000: 0x800,
			            0x80000001: 0x8020820,
			            0x80000002: 0x8000820,
			            0x80000003: 0x8000000,
			            0x80000004: 0x8020000,
			            0x80000005: 0x20800,
			            0x80000006: 0x20820,
			            0x80000007: 0x20,
			            0x80000008: 0x8000020,
			            0x80000009: 0x820,
			            0x8000000a: 0x20020,
			            0x8000000b: 0x8020800,
			            0x8000000c: 0x0,
			            0x8000000d: 0x8020020,
			            0x8000000e: 0x8000800,
			            0x8000000f: 0x20000,
			            0x10: 0x20820,
			            0x11: 0x8020800,
			            0x12: 0x20,
			            0x13: 0x800,
			            0x14: 0x8000800,
			            0x15: 0x8000020,
			            0x16: 0x8020020,
			            0x17: 0x20000,
			            0x18: 0x0,
			            0x19: 0x20020,
			            0x1a: 0x8020000,
			            0x1b: 0x8000820,
			            0x1c: 0x8020820,
			            0x1d: 0x20800,
			            0x1e: 0x820,
			            0x1f: 0x8000000,
			            0x80000010: 0x20000,
			            0x80000011: 0x800,
			            0x80000012: 0x8020020,
			            0x80000013: 0x20820,
			            0x80000014: 0x20,
			            0x80000015: 0x8020000,
			            0x80000016: 0x8000000,
			            0x80000017: 0x8000820,
			            0x80000018: 0x8020820,
			            0x80000019: 0x8000020,
			            0x8000001a: 0x8000800,
			            0x8000001b: 0x0,
			            0x8000001c: 0x20800,
			            0x8000001d: 0x820,
			            0x8000001e: 0x20020,
			            0x8000001f: 0x8020800
			        }
			    ];

			    // Masks that select the SBOX input
			    var SBOX_MASK = [
			        0xf8000001, 0x1f800000, 0x01f80000, 0x001f8000,
			        0x0001f800, 0x00001f80, 0x000001f8, 0x8000001f
			    ];

			    /**
			     * DES block cipher algorithm.
			     */
			    var DES = C_algo.DES = BlockCipher.extend({
			        _doReset: function () {
			            // Shortcuts
			            var key = this._key;
			            var keyWords = key.words;

			            // Select 56 bits according to PC1
			            var keyBits = [];
			            for (var i = 0; i < 56; i++) {
			                var keyBitPos = PC1[i] - 1;
			                keyBits[i] = (keyWords[keyBitPos >>> 5] >>> (31 - keyBitPos % 32)) & 1;
			            }

			            // Assemble 16 subkeys
			            var subKeys = this._subKeys = [];
			            for (var nSubKey = 0; nSubKey < 16; nSubKey++) {
			                // Create subkey
			                var subKey = subKeys[nSubKey] = [];

			                // Shortcut
			                var bitShift = BIT_SHIFTS[nSubKey];

			                // Select 48 bits according to PC2
			                for (var i = 0; i < 24; i++) {
			                    // Select from the left 28 key bits
			                    subKey[(i / 6) | 0] |= keyBits[((PC2[i] - 1) + bitShift) % 28] << (31 - i % 6);

			                    // Select from the right 28 key bits
			                    subKey[4 + ((i / 6) | 0)] |= keyBits[28 + (((PC2[i + 24] - 1) + bitShift) % 28)] << (31 - i % 6);
			                }

			                // Since each subkey is applied to an expanded 32-bit input,
			                // the subkey can be broken into 8 values scaled to 32-bits,
			                // which allows the key to be used without expansion
			                subKey[0] = (subKey[0] << 1) | (subKey[0] >>> 31);
			                for (var i = 1; i < 7; i++) {
			                    subKey[i] = subKey[i] >>> ((i - 1) * 4 + 3);
			                }
			                subKey[7] = (subKey[7] << 5) | (subKey[7] >>> 27);
			            }

			            // Compute inverse subkeys
			            var invSubKeys = this._invSubKeys = [];
			            for (var i = 0; i < 16; i++) {
			                invSubKeys[i] = subKeys[15 - i];
			            }
			        },

			        encryptBlock: function (M, offset) {
			            this._doCryptBlock(M, offset, this._subKeys);
			        },

			        decryptBlock: function (M, offset) {
			            this._doCryptBlock(M, offset, this._invSubKeys);
			        },

			        _doCryptBlock: function (M, offset, subKeys) {
			            // Get input
			            this._lBlock = M[offset];
			            this._rBlock = M[offset + 1];

			            // Initial permutation
			            exchangeLR.call(this, 4,  0x0f0f0f0f);
			            exchangeLR.call(this, 16, 0x0000ffff);
			            exchangeRL.call(this, 2,  0x33333333);
			            exchangeRL.call(this, 8,  0x00ff00ff);
			            exchangeLR.call(this, 1,  0x55555555);

			            // Rounds
			            for (var round = 0; round < 16; round++) {
			                // Shortcuts
			                var subKey = subKeys[round];
			                var lBlock = this._lBlock;
			                var rBlock = this._rBlock;

			                // Feistel function
			                var f = 0;
			                for (var i = 0; i < 8; i++) {
			                    f |= SBOX_P[i][((rBlock ^ subKey[i]) & SBOX_MASK[i]) >>> 0];
			                }
			                this._lBlock = rBlock;
			                this._rBlock = lBlock ^ f;
			            }

			            // Undo swap from last round
			            var t = this._lBlock;
			            this._lBlock = this._rBlock;
			            this._rBlock = t;

			            // Final permutation
			            exchangeLR.call(this, 1,  0x55555555);
			            exchangeRL.call(this, 8,  0x00ff00ff);
			            exchangeRL.call(this, 2,  0x33333333);
			            exchangeLR.call(this, 16, 0x0000ffff);
			            exchangeLR.call(this, 4,  0x0f0f0f0f);

			            // Set output
			            M[offset] = this._lBlock;
			            M[offset + 1] = this._rBlock;
			        },

			        keySize: 64/32,

			        ivSize: 64/32,

			        blockSize: 64/32
			    });

			    // Swap bits across the left and right words
			    function exchangeLR(offset, mask) {
			        var t = ((this._lBlock >>> offset) ^ this._rBlock) & mask;
			        this._rBlock ^= t;
			        this._lBlock ^= t << offset;
			    }

			    function exchangeRL(offset, mask) {
			        var t = ((this._rBlock >>> offset) ^ this._lBlock) & mask;
			        this._lBlock ^= t;
			        this._rBlock ^= t << offset;
			    }

			    /**
			     * Shortcut functions to the cipher's object interface.
			     *
			     * @example
			     *
			     *     var ciphertext = CryptoJS.DES.encrypt(message, key, cfg);
			     *     var plaintext  = CryptoJS.DES.decrypt(ciphertext, key, cfg);
			     */
			    C.DES = BlockCipher._createHelper(DES);

			    /**
			     * Triple-DES block cipher algorithm.
			     */
			    var TripleDES = C_algo.TripleDES = BlockCipher.extend({
			        _doReset: function () {
			            // Shortcuts
			            var key = this._key;
			            var keyWords = key.words;
			            // Make sure the key length is valid (64, 128 or >= 192 bit)
			            if (keyWords.length !== 2 && keyWords.length !== 4 && keyWords.length < 6) {
			                throw new Error('Invalid key length - 3DES requires the key length to be 64, 128, 192 or >192.');
			            }

			            // Extend the key according to the keying options defined in 3DES standard
			            var key1 = keyWords.slice(0, 2);
			            var key2 = keyWords.length < 4 ? keyWords.slice(0, 2) : keyWords.slice(2, 4);
			            var key3 = keyWords.length < 6 ? keyWords.slice(0, 2) : keyWords.slice(4, 6);

			            // Create DES instances
			            this._des1 = DES.createEncryptor(WordArray.create(key1));
			            this._des2 = DES.createEncryptor(WordArray.create(key2));
			            this._des3 = DES.createEncryptor(WordArray.create(key3));
			        },

			        encryptBlock: function (M, offset) {
			            this._des1.encryptBlock(M, offset);
			            this._des2.decryptBlock(M, offset);
			            this._des3.encryptBlock(M, offset);
			        },

			        decryptBlock: function (M, offset) {
			            this._des3.decryptBlock(M, offset);
			            this._des2.encryptBlock(M, offset);
			            this._des1.decryptBlock(M, offset);
			        },

			        keySize: 192/32,

			        ivSize: 64/32,

			        blockSize: 64/32
			    });

			    /**
			     * Shortcut functions to the cipher's object interface.
			     *
			     * @example
			     *
			     *     var ciphertext = CryptoJS.TripleDES.encrypt(message, key, cfg);
			     *     var plaintext  = CryptoJS.TripleDES.decrypt(ciphertext, key, cfg);
			     */
			    C.TripleDES = BlockCipher._createHelper(TripleDES);
			}());


			return CryptoJS.TripleDES;

		}));
} (tripledes));
	return tripledesExports;
}

var rc4Exports = {};
var rc4 = {
  get exports(){ return rc4Exports; },
  set exports(v){ rc4Exports = v; },
};

var hasRequiredRc4;

function requireRc4 () {
	if (hasRequiredRc4) return rc4Exports;
	hasRequiredRc4 = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireEncBase64(), requireMd5(), requireEvpkdf(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var StreamCipher = C_lib.StreamCipher;
			    var C_algo = C.algo;

			    /**
			     * RC4 stream cipher algorithm.
			     */
			    var RC4 = C_algo.RC4 = StreamCipher.extend({
			        _doReset: function () {
			            // Shortcuts
			            var key = this._key;
			            var keyWords = key.words;
			            var keySigBytes = key.sigBytes;

			            // Init sbox
			            var S = this._S = [];
			            for (var i = 0; i < 256; i++) {
			                S[i] = i;
			            }

			            // Key setup
			            for (var i = 0, j = 0; i < 256; i++) {
			                var keyByteIndex = i % keySigBytes;
			                var keyByte = (keyWords[keyByteIndex >>> 2] >>> (24 - (keyByteIndex % 4) * 8)) & 0xff;

			                j = (j + S[i] + keyByte) % 256;

			                // Swap
			                var t = S[i];
			                S[i] = S[j];
			                S[j] = t;
			            }

			            // Counters
			            this._i = this._j = 0;
			        },

			        _doProcessBlock: function (M, offset) {
			            M[offset] ^= generateKeystreamWord.call(this);
			        },

			        keySize: 256/32,

			        ivSize: 0
			    });

			    function generateKeystreamWord() {
			        // Shortcuts
			        var S = this._S;
			        var i = this._i;
			        var j = this._j;

			        // Generate keystream word
			        var keystreamWord = 0;
			        for (var n = 0; n < 4; n++) {
			            i = (i + 1) % 256;
			            j = (j + S[i]) % 256;

			            // Swap
			            var t = S[i];
			            S[i] = S[j];
			            S[j] = t;

			            keystreamWord |= S[(S[i] + S[j]) % 256] << (24 - n * 8);
			        }

			        // Update counters
			        this._i = i;
			        this._j = j;

			        return keystreamWord;
			    }

			    /**
			     * Shortcut functions to the cipher's object interface.
			     *
			     * @example
			     *
			     *     var ciphertext = CryptoJS.RC4.encrypt(message, key, cfg);
			     *     var plaintext  = CryptoJS.RC4.decrypt(ciphertext, key, cfg);
			     */
			    C.RC4 = StreamCipher._createHelper(RC4);

			    /**
			     * Modified RC4 stream cipher algorithm.
			     */
			    var RC4Drop = C_algo.RC4Drop = RC4.extend({
			        /**
			         * Configuration options.
			         *
			         * @property {number} drop The number of keystream words to drop. Default 192
			         */
			        cfg: RC4.cfg.extend({
			            drop: 192
			        }),

			        _doReset: function () {
			            RC4._doReset.call(this);

			            // Drop
			            for (var i = this.cfg.drop; i > 0; i--) {
			                generateKeystreamWord.call(this);
			            }
			        }
			    });

			    /**
			     * Shortcut functions to the cipher's object interface.
			     *
			     * @example
			     *
			     *     var ciphertext = CryptoJS.RC4Drop.encrypt(message, key, cfg);
			     *     var plaintext  = CryptoJS.RC4Drop.decrypt(ciphertext, key, cfg);
			     */
			    C.RC4Drop = StreamCipher._createHelper(RC4Drop);
			}());


			return CryptoJS.RC4;

		}));
} (rc4));
	return rc4Exports;
}

var rabbitExports = {};
var rabbit = {
  get exports(){ return rabbitExports; },
  set exports(v){ rabbitExports = v; },
};

var hasRequiredRabbit;

function requireRabbit () {
	if (hasRequiredRabbit) return rabbitExports;
	hasRequiredRabbit = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireEncBase64(), requireMd5(), requireEvpkdf(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var StreamCipher = C_lib.StreamCipher;
			    var C_algo = C.algo;

			    // Reusable objects
			    var S  = [];
			    var C_ = [];
			    var G  = [];

			    /**
			     * Rabbit stream cipher algorithm
			     */
			    var Rabbit = C_algo.Rabbit = StreamCipher.extend({
			        _doReset: function () {
			            // Shortcuts
			            var K = this._key.words;
			            var iv = this.cfg.iv;

			            // Swap endian
			            for (var i = 0; i < 4; i++) {
			                K[i] = (((K[i] << 8)  | (K[i] >>> 24)) & 0x00ff00ff) |
			                       (((K[i] << 24) | (K[i] >>> 8))  & 0xff00ff00);
			            }

			            // Generate initial state values
			            var X = this._X = [
			                K[0], (K[3] << 16) | (K[2] >>> 16),
			                K[1], (K[0] << 16) | (K[3] >>> 16),
			                K[2], (K[1] << 16) | (K[0] >>> 16),
			                K[3], (K[2] << 16) | (K[1] >>> 16)
			            ];

			            // Generate initial counter values
			            var C = this._C = [
			                (K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
			                (K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
			                (K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
			                (K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff)
			            ];

			            // Carry bit
			            this._b = 0;

			            // Iterate the system four times
			            for (var i = 0; i < 4; i++) {
			                nextState.call(this);
			            }

			            // Modify the counters
			            for (var i = 0; i < 8; i++) {
			                C[i] ^= X[(i + 4) & 7];
			            }

			            // IV setup
			            if (iv) {
			                // Shortcuts
			                var IV = iv.words;
			                var IV_0 = IV[0];
			                var IV_1 = IV[1];

			                // Generate four subvectors
			                var i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff) | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
			                var i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff) | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
			                var i1 = (i0 >>> 16) | (i2 & 0xffff0000);
			                var i3 = (i2 << 16)  | (i0 & 0x0000ffff);

			                // Modify counter values
			                C[0] ^= i0;
			                C[1] ^= i1;
			                C[2] ^= i2;
			                C[3] ^= i3;
			                C[4] ^= i0;
			                C[5] ^= i1;
			                C[6] ^= i2;
			                C[7] ^= i3;

			                // Iterate the system four times
			                for (var i = 0; i < 4; i++) {
			                    nextState.call(this);
			                }
			            }
			        },

			        _doProcessBlock: function (M, offset) {
			            // Shortcut
			            var X = this._X;

			            // Iterate the system
			            nextState.call(this);

			            // Generate four keystream words
			            S[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
			            S[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
			            S[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
			            S[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

			            for (var i = 0; i < 4; i++) {
			                // Swap endian
			                S[i] = (((S[i] << 8)  | (S[i] >>> 24)) & 0x00ff00ff) |
			                       (((S[i] << 24) | (S[i] >>> 8))  & 0xff00ff00);

			                // Encrypt
			                M[offset + i] ^= S[i];
			            }
			        },

			        blockSize: 128/32,

			        ivSize: 64/32
			    });

			    function nextState() {
			        // Shortcuts
			        var X = this._X;
			        var C = this._C;

			        // Save old counter values
			        for (var i = 0; i < 8; i++) {
			            C_[i] = C[i];
			        }

			        // Calculate new counter values
			        C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
			        C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_[0] >>> 0) ? 1 : 0)) | 0;
			        C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_[1] >>> 0) ? 1 : 0)) | 0;
			        C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_[2] >>> 0) ? 1 : 0)) | 0;
			        C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_[3] >>> 0) ? 1 : 0)) | 0;
			        C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_[4] >>> 0) ? 1 : 0)) | 0;
			        C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_[5] >>> 0) ? 1 : 0)) | 0;
			        C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_[6] >>> 0) ? 1 : 0)) | 0;
			        this._b = (C[7] >>> 0) < (C_[7] >>> 0) ? 1 : 0;

			        // Calculate the g-values
			        for (var i = 0; i < 8; i++) {
			            var gx = X[i] + C[i];

			            // Construct high and low argument for squaring
			            var ga = gx & 0xffff;
			            var gb = gx >>> 16;

			            // Calculate high and low result of squaring
			            var gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
			            var gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

			            // High XOR low
			            G[i] = gh ^ gl;
			        }

			        // Calculate new state values
			        X[0] = (G[0] + ((G[7] << 16) | (G[7] >>> 16)) + ((G[6] << 16) | (G[6] >>> 16))) | 0;
			        X[1] = (G[1] + ((G[0] << 8)  | (G[0] >>> 24)) + G[7]) | 0;
			        X[2] = (G[2] + ((G[1] << 16) | (G[1] >>> 16)) + ((G[0] << 16) | (G[0] >>> 16))) | 0;
			        X[3] = (G[3] + ((G[2] << 8)  | (G[2] >>> 24)) + G[1]) | 0;
			        X[4] = (G[4] + ((G[3] << 16) | (G[3] >>> 16)) + ((G[2] << 16) | (G[2] >>> 16))) | 0;
			        X[5] = (G[5] + ((G[4] << 8)  | (G[4] >>> 24)) + G[3]) | 0;
			        X[6] = (G[6] + ((G[5] << 16) | (G[5] >>> 16)) + ((G[4] << 16) | (G[4] >>> 16))) | 0;
			        X[7] = (G[7] + ((G[6] << 8)  | (G[6] >>> 24)) + G[5]) | 0;
			    }

			    /**
			     * Shortcut functions to the cipher's object interface.
			     *
			     * @example
			     *
			     *     var ciphertext = CryptoJS.Rabbit.encrypt(message, key, cfg);
			     *     var plaintext  = CryptoJS.Rabbit.decrypt(ciphertext, key, cfg);
			     */
			    C.Rabbit = StreamCipher._createHelper(Rabbit);
			}());


			return CryptoJS.Rabbit;

		}));
} (rabbit));
	return rabbitExports;
}

var rabbitLegacyExports = {};
var rabbitLegacy = {
  get exports(){ return rabbitLegacyExports; },
  set exports(v){ rabbitLegacyExports = v; },
};

var hasRequiredRabbitLegacy;

function requireRabbitLegacy () {
	if (hasRequiredRabbitLegacy) return rabbitLegacyExports;
	hasRequiredRabbitLegacy = 1;
	(function (module, exports) {
(function (root, factory, undef) {
			{
				// CommonJS
				module.exports = factory(requireCore(), requireEncBase64(), requireMd5(), requireEvpkdf(), requireCipherCore());
			}
		}(commonjsGlobal, function (CryptoJS) {

			(function () {
			    // Shortcuts
			    var C = CryptoJS;
			    var C_lib = C.lib;
			    var StreamCipher = C_lib.StreamCipher;
			    var C_algo = C.algo;

			    // Reusable objects
			    var S  = [];
			    var C_ = [];
			    var G  = [];

			    /**
			     * Rabbit stream cipher algorithm.
			     *
			     * This is a legacy version that neglected to convert the key to little-endian.
			     * This error doesn't affect the cipher's security,
			     * but it does affect its compatibility with other implementations.
			     */
			    var RabbitLegacy = C_algo.RabbitLegacy = StreamCipher.extend({
			        _doReset: function () {
			            // Shortcuts
			            var K = this._key.words;
			            var iv = this.cfg.iv;

			            // Generate initial state values
			            var X = this._X = [
			                K[0], (K[3] << 16) | (K[2] >>> 16),
			                K[1], (K[0] << 16) | (K[3] >>> 16),
			                K[2], (K[1] << 16) | (K[0] >>> 16),
			                K[3], (K[2] << 16) | (K[1] >>> 16)
			            ];

			            // Generate initial counter values
			            var C = this._C = [
			                (K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
			                (K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
			                (K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
			                (K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff)
			            ];

			            // Carry bit
			            this._b = 0;

			            // Iterate the system four times
			            for (var i = 0; i < 4; i++) {
			                nextState.call(this);
			            }

			            // Modify the counters
			            for (var i = 0; i < 8; i++) {
			                C[i] ^= X[(i + 4) & 7];
			            }

			            // IV setup
			            if (iv) {
			                // Shortcuts
			                var IV = iv.words;
			                var IV_0 = IV[0];
			                var IV_1 = IV[1];

			                // Generate four subvectors
			                var i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff) | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
			                var i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff) | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
			                var i1 = (i0 >>> 16) | (i2 & 0xffff0000);
			                var i3 = (i2 << 16)  | (i0 & 0x0000ffff);

			                // Modify counter values
			                C[0] ^= i0;
			                C[1] ^= i1;
			                C[2] ^= i2;
			                C[3] ^= i3;
			                C[4] ^= i0;
			                C[5] ^= i1;
			                C[6] ^= i2;
			                C[7] ^= i3;

			                // Iterate the system four times
			                for (var i = 0; i < 4; i++) {
			                    nextState.call(this);
			                }
			            }
			        },

			        _doProcessBlock: function (M, offset) {
			            // Shortcut
			            var X = this._X;

			            // Iterate the system
			            nextState.call(this);

			            // Generate four keystream words
			            S[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
			            S[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
			            S[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
			            S[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

			            for (var i = 0; i < 4; i++) {
			                // Swap endian
			                S[i] = (((S[i] << 8)  | (S[i] >>> 24)) & 0x00ff00ff) |
			                       (((S[i] << 24) | (S[i] >>> 8))  & 0xff00ff00);

			                // Encrypt
			                M[offset + i] ^= S[i];
			            }
			        },

			        blockSize: 128/32,

			        ivSize: 64/32
			    });

			    function nextState() {
			        // Shortcuts
			        var X = this._X;
			        var C = this._C;

			        // Save old counter values
			        for (var i = 0; i < 8; i++) {
			            C_[i] = C[i];
			        }

			        // Calculate new counter values
			        C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
			        C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_[0] >>> 0) ? 1 : 0)) | 0;
			        C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_[1] >>> 0) ? 1 : 0)) | 0;
			        C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_[2] >>> 0) ? 1 : 0)) | 0;
			        C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_[3] >>> 0) ? 1 : 0)) | 0;
			        C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_[4] >>> 0) ? 1 : 0)) | 0;
			        C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_[5] >>> 0) ? 1 : 0)) | 0;
			        C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_[6] >>> 0) ? 1 : 0)) | 0;
			        this._b = (C[7] >>> 0) < (C_[7] >>> 0) ? 1 : 0;

			        // Calculate the g-values
			        for (var i = 0; i < 8; i++) {
			            var gx = X[i] + C[i];

			            // Construct high and low argument for squaring
			            var ga = gx & 0xffff;
			            var gb = gx >>> 16;

			            // Calculate high and low result of squaring
			            var gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
			            var gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

			            // High XOR low
			            G[i] = gh ^ gl;
			        }

			        // Calculate new state values
			        X[0] = (G[0] + ((G[7] << 16) | (G[7] >>> 16)) + ((G[6] << 16) | (G[6] >>> 16))) | 0;
			        X[1] = (G[1] + ((G[0] << 8)  | (G[0] >>> 24)) + G[7]) | 0;
			        X[2] = (G[2] + ((G[1] << 16) | (G[1] >>> 16)) + ((G[0] << 16) | (G[0] >>> 16))) | 0;
			        X[3] = (G[3] + ((G[2] << 8)  | (G[2] >>> 24)) + G[1]) | 0;
			        X[4] = (G[4] + ((G[3] << 16) | (G[3] >>> 16)) + ((G[2] << 16) | (G[2] >>> 16))) | 0;
			        X[5] = (G[5] + ((G[4] << 8)  | (G[4] >>> 24)) + G[3]) | 0;
			        X[6] = (G[6] + ((G[5] << 16) | (G[5] >>> 16)) + ((G[4] << 16) | (G[4] >>> 16))) | 0;
			        X[7] = (G[7] + ((G[6] << 8)  | (G[6] >>> 24)) + G[5]) | 0;
			    }

			    /**
			     * Shortcut functions to the cipher's object interface.
			     *
			     * @example
			     *
			     *     var ciphertext = CryptoJS.RabbitLegacy.encrypt(message, key, cfg);
			     *     var plaintext  = CryptoJS.RabbitLegacy.decrypt(ciphertext, key, cfg);
			     */
			    C.RabbitLegacy = StreamCipher._createHelper(RabbitLegacy);
			}());


			return CryptoJS.RabbitLegacy;

		}));
} (rabbitLegacy));
	return rabbitLegacyExports;
}

(function (module, exports) {
(function (root, factory, undef) {
		{
			// CommonJS
			module.exports = factory(requireCore(), requireX64Core(), requireLibTypedarrays(), requireEncUtf16(), requireEncBase64(), requireEncBase64url(), requireMd5(), requireSha1(), requireSha256(), requireSha224(), requireSha512(), requireSha384(), requireSha3(), requireRipemd160(), requireHmac(), requirePbkdf2(), requireEvpkdf(), requireCipherCore(), requireModeCfb(), requireModeCtr(), requireModeCtrGladman(), requireModeOfb(), requireModeEcb(), requirePadAnsix923(), requirePadIso10126(), requirePadIso97971(), requirePadZeropadding(), requirePadNopadding(), requireFormatHex(), requireAes(), requireTripledes(), requireRc4(), requireRabbit(), requireRabbitLegacy());
		}
	}(commonjsGlobal, function (CryptoJS) {

		return CryptoJS;

	}));
} (cryptoJs));

var transaction = {};

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
	const crypto_js_1 = __importDefault(cryptoJsExports);
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
	        const hash = crypto_js_1.default.SHA256(toBinaryString(buf));
	        return encode(convertToUint8(hash));
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
	function toBinaryString(array) {
	    var i, len = array.length, b_str = "";
	    for (i = 0; i < len; i++) {
	        b_str += String.fromCharCode(array[i]);
	    }
	    return b_str;
	}
	function convertToUint8(wordArray) {
	    var len = wordArray.words.length, u8_array = new Uint8Array(len << 2), offset = 0, word, i;
	    for (i = 0; i < len; i++) {
	        word = wordArray.words[i];
	        u8_array[offset++] = word >> 24;
	        u8_array[offset++] = (word >> 16) & 0xff;
	        u8_array[offset++] = (word >> 8) & 0xff;
	        u8_array[offset++] = word & 0xff;
	    }
	    return u8_array;
	}
} (transaction));

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
Object.defineProperty(address, "__esModule", { value: true });
address.Address = void 0;
const ed = __importStar(lib);
const crypto_js_1 = __importDefault(cryptoJsExports);
const transaction_1 = transaction;
const NETWORK = 0xA1;
const WALLET_TYPE = 1;
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
    const decoder = new TextDecoder("utf-8");
    new TextEncoder();
    const shaHash = crypto_js_1.default.SHA256(decoder.decode(pubKey));
    const ripemdHash = crypto_js_1.default.RIPEMD160(shaHash);
    const addr = Uint8Array.from([NETWORK, WALLET_TYPE, ...toUint8(ripemdHash)]);
    const stage1 = crypto_js_1.default.SHA256(ripemdHash);
    const stage2 = crypto_js_1.default.SHA256(stage1);
    const rawStr = convertUint8ArrayToBinaryString(addr) + convertUint8ArrayToBinaryString(toUint8(stage2).slice(0, 4));
    const bytes = Uint8Array.from(convertBinaryStringToUint8Array(rawStr));
    return 'kryo:' + transaction_1.base58.encode(bytes);
}
function toUint8(wordArray) {
    var len = wordArray.words.length, u8_array = new Uint8Array(len << 2), offset = 0, word, i;
    for (i = 0; i < len; i++) {
        word = wordArray.words[i];
        u8_array[offset++] = word >> 24;
        u8_array[offset++] = (word >> 16) & 0xff;
        u8_array[offset++] = (word >> 8) & 0xff;
        u8_array[offset++] = word & 0xff;
    }
    return u8_array;
}
function convertUint8ArrayToBinaryString(u8Array) {
    var i, len = u8Array.length, b_str = "";
    for (i = 0; i < len; i++) {
        b_str += String.fromCharCode(u8Array[i]);
    }
    return b_str;
}
function convertBinaryStringToUint8Array(bStr) {
    var i, len = bStr.length, u8_array = new Uint8Array(len);
    for (i = 0; i < len; i++) {
        u8_array[i] = bStr.charCodeAt(i);
    }
    return u8_array;
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

module.exports = index;