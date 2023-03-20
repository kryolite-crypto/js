"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
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
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transaction = exports.NULL_ADDRESS = exports.TransactionType = void 0;
const ed = __importStar(require("@noble/ed25519"));
const base58_encoding_1 = __importDefault(require("@dwlib/base58-encoding"));
const base58 = new base58_encoding_1.default('123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ');
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
        const pk = ed.utils.bytesToHex(privateKey);
        const buf = new Array();
        buf.push(...toUint8(new Uint16Array([this.TransactionType])));
        buf.push(decode(this.PublicKey));
        buf.push(decode(this.To.replace('kryo:', '')));
        buf.push(...toUint8(new BigUint64Array(this.Value)));
        buf.push(...toUint8(new BigUint64Array(this.MaxFee)));
        if (this.Data) {
            buf.push(this.Data);
        }
        buf.push(...toUint8(new Uint32Array(this.Nonce)));
        const message = ed.utils.bytesToHex(new Uint8Array(buf));
        this.Signature = encode(await ed.sign(message, pk));
    }
    async Verify() {
        if (!this.Signature || !this.PublicKey) {
            return false;
        }
        const buf = new Array();
        buf.push(...toUint8(new Uint16Array([this.TransactionType])));
        buf.push(decode(this.PublicKey));
        buf.push(decode(this.To.replace('kryo:', '')));
        buf.push(...toUint8(new BigUint64Array(this.Value)));
        buf.push(...toUint8(new BigUint64Array(this.MaxFee)));
        if (this.Data) {
            buf.push(...this.Data);
        }
        buf.push(...toUint8(new Uint32Array(this.Nonce)));
        const message = ed.utils.bytesToHex(new Uint8Array(buf));
        return await ed.verify(decode(this.Signature), message, this.PublicKey);
    }
}
exports.Transaction = Transaction;
function toUint8(array) {
    return new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
}
function decode(str) {
    return base58.decodeToBytes(str);
}
function encode(bytes) {
    return base58.encode(bytes);
}
