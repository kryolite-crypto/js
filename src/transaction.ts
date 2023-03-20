import * as ed from '@noble/ed25519';
import Base58Encoding from '@dwlib/base58-encoding';

const base58 = new Base58Encoding('123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ');

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

    public async Sign(privateKey: Uint8Array): Promise<void>
    {
        const pk = ed.utils.bytesToHex(privateKey);

        const buf = new Array();
        buf.push(...toUint8(new Uint16Array([this.TransactionType])));
        buf.push(decode(this.PublicKey));
        buf.push(decode(this.To.replace('kryo:', '')));
        buf.push(...toUint8(new BigUint64Array(this.Value)));
        buf.push(...toUint8(new BigUint64Array(this.MaxFee)));
        
        if (this.Data)
        {
            buf.push(this.Data);
        }

        buf.push(...toUint8(new Uint32Array(this.Nonce)));

        const message = ed.utils.bytesToHex(new Uint8Array(buf));
        this.Signature = encode(await ed.sign(message, pk));
    }

    public async Verify(): Promise<boolean>
    {
        if (!this.Signature || !this.PublicKey)
        {
            return false;
        }

        const buf = new Array();
        buf.push(...toUint8(new Uint16Array([this.TransactionType])));
        buf.push(decode(this.PublicKey));
        buf.push(decode(this.To.replace('kryo:', '')));
        buf.push(...toUint8(new BigUint64Array(this.Value)));
        buf.push(...toUint8(new BigUint64Array(this.MaxFee)));

        if (this.Data)
        {
            buf.push(...this.Data);
        }

        buf.push(...toUint8(new Uint32Array(this.Nonce)));

        const message = ed.utils.bytesToHex(new Uint8Array(buf));
        return await ed.verify(decode(this.Signature), message, this.PublicKey);
    }
}

function toUint8(array: Uint16Array | Uint32Array | BigUint64Array): Uint8Array
{
    return new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
}

function decode(str: string): Uint8Array
{
    return base58.decodeToBytes(str);
}

function encode(bytes: Uint8Array): string
{
    return base58.encode(bytes);
}
