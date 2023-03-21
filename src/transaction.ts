import * as ed from '@noble/ed25519';
import CryptoJS from 'crypto-js';
import bs58 from 'base-x';

export const base58 = bs58('123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ');

export enum TransactionType
{
    PAYMENT,
    MINER_FEE,
    VALIDATOR_FEE,
    DEV_FEE,
    CONTRACT
}

export const NULL_ADDRESS = 'kryo:11111111111111111111111111';

export class Transaction
{
    public TransactionType: TransactionType = 0;
    public PublicKey?: string;
    public To: string = NULL_ADDRESS;
    public Value: number = 0;
    public MaxFee: number = 0;
    public Data?: Uint8Array;
    public Nonce: number = 0;
    public Signature?: string;

    public async Sign(privateKey: string): Promise<void>
    {
        const pk = ed.utils.bytesToHex(decode(privateKey));

        const buf = new Array<number>();
        buf.push(...toUint8(Uint16Array.from([this.TransactionType])));
        buf.push(...decode(this.PublicKey));
        buf.push(...decode(this.To.replace('kryo:', '')));
        buf.push(...toUint8(BigUint64Array.from([BigInt(this.Value)])));
        buf.push(...toUint8(BigUint64Array.from([BigInt(this.MaxFee)])));
        
        if (this.Data)
        {
            buf.push(...this.Data);
        }

        buf.push(...toUint8(Uint32Array.from([this.Nonce])));

        const message = ed.utils.bytesToHex(Uint8Array.from(buf));
        this.Signature = encode(await ed.sign(message, pk));
    }

    public async Verify(): Promise<boolean>
    {
        if (!this.Signature || !this.PublicKey)
        {
            return false;
        }

        const buf = new Array<number>();
        buf.push(...toUint8(Uint16Array.from([this.TransactionType])));
        buf.push(...decode(this.PublicKey));
        buf.push(...decode(this.To.replace('kryo:', '')));
        buf.push(...toUint8(BigUint64Array.from([BigInt(this.Value)])));
        buf.push(...toUint8(BigUint64Array.from([BigInt(this.MaxFee)])));

        if (this.Data)
        {
            buf.push(...this.Data);
        }

        buf.push(...toUint8(Uint32Array.from([this.Nonce])));

        const message = ed.utils.bytesToHex(Uint8Array.from(buf));
        return await ed.verify(decode(this.Signature), message, decode(this.PublicKey));
    }

    public async CalculateHash(): Promise<string>
    {
        const buf = new Array<number>();

        if (this.TransactionType == TransactionType.PAYMENT || this.TransactionType == TransactionType.CONTRACT) 
        {
            buf.push(...decode(this.PublicKey));
        }

        buf.push(...decode(this.To.replace('kryo:', '')));
        buf.push(...toUint8(BigUint64Array.from([BigInt(this.Value)])));
        buf.push(...toUint8(BigUint64Array.from([BigInt(this.MaxFee)])));

        if (this.Data)
        {
            buf.push(...this.Data);
        }

        buf.push(...toUint8(Uint32Array.from([this.Nonce])));

        if (this.TransactionType == TransactionType.PAYMENT || this.TransactionType == TransactionType.CONTRACT) 
        {
            buf.push(...decode(this.Signature));
        }

        const hash = CryptoJS.SHA256(toBinaryString(buf));

        return encode(convertToUint8(hash));
    }

    public ToJsonString(): string
    {
        return JSON.stringify(this);
    }
}

function toUint8(array: Uint16Array | Uint32Array | BigUint64Array): Uint8Array
{
    return new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
}

function decode(str: string): Uint8Array
{
    return base58.decode(str);
}

function encode(bytes: Uint8Array): string
{
    return base58.encode(bytes);
}

function toBinaryString(array: Array<number>) {
	var i, len = array.length, b_str = "";

	for (i=0; i<len; i++) {
		b_str += String.fromCharCode(array[i]);
	}
	return b_str;
}

function convertToUint8(wordArray: CryptoJS.lib.WordArray) {
	var len = wordArray.words.length,
		u8_array = new Uint8Array(len << 2),
		offset = 0, word, i
	;
	for (i=0; i<len; i++) {
		word = wordArray.words[i];
		u8_array[offset++] = word >> 24;
		u8_array[offset++] = (word >> 16) & 0xff;
		u8_array[offset++] = (word >> 8) & 0xff;
		u8_array[offset++] = word & 0xff;
	}
	return u8_array;
}