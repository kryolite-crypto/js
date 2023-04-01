
import * as ed from '@noble/ed25519';
import { base58 } from './transaction';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';

const NETWORK = 0xA1;
const WALLET_TYPE = 0;

export class Address
{
    public PrivateKey: string;
    public PublicKey: string;
    public Address: string;

    public static async Create(): Promise<Address>
    {
        const address = new Address();

        const privKey = ed.utils.randomPrivateKey();
        const pubKey = await ed.getPublicKey(privKey);

        address.PrivateKey = base58.encode(privKey);
        address.PublicKey = base58.encode(pubKey);
        address.Address = toAddress(pubKey);

        return address;
    }

    public static async Import(privKeyStr: string): Promise<Address>
    {
        const address = new Address();

        const pubKey = await ed.getPublicKey(base58.decode(privKeyStr));

        address.PrivateKey = privKeyStr;
        address.PublicKey = base58.encode(pubKey);
        address.Address = toAddress(pubKey);

        return address;
    }
}

function toAddress(pubKey: Uint8Array)
{
    const encoder = new TextEncoder();

    const shaHash = sha256(pubKey);
    const ripemdHash = ripemd160(shaHash);

    const addr = Uint8Array.from([NETWORK, WALLET_TYPE, ...ripemdHash]);

    const ripemdBytes = Uint8Array.from([...encoder.encode("kryo:"), ...addr]);

    const stage1 = sha256(ripemdBytes);
    const stage2 = sha256(stage1);

    const final = [...addr, ...stage2.slice(0, 4)];
    const bytes = Uint8Array.from(final);

    return 'kryo:' + base58.encode(bytes);
}
