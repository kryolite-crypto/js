
import * as ed from '@noble/ed25519';
import CryptoJS from 'crypto-js';
import { base58 } from './transaction';

const NETWORK = 0xA1;
const WALLET_TYPE = 1;

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
    const decoder = new TextDecoder("utf-8");
    const encoder = new TextEncoder();

    const shaHash = CryptoJS.SHA256(decoder.decode(pubKey));
    const ripemdHash = CryptoJS.RIPEMD160(shaHash);

    const addr = Uint8Array.from([NETWORK, WALLET_TYPE, ...toUint8(ripemdHash)]);

    const stage1 = CryptoJS.SHA256(ripemdHash);
    const stage2 = CryptoJS.SHA256(stage1);

    const rawStr = convertUint8ArrayToBinaryString(addr) + convertUint8ArrayToBinaryString(toUint8(stage2).slice(0, 4));
    const bytes = Uint8Array.from(convertBinaryStringToUint8Array(rawStr));

    return 'kryo:' + base58.encode(bytes);
}

function toUint8(wordArray: CryptoJS.lib.WordArray) {
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

function convertUint8ArrayToBinaryString(u8Array: Uint8Array) {
	var i, len = u8Array.length, b_str = "";
	for (i=0; i<len; i++) {
		b_str += String.fromCharCode(u8Array[i]);
	}
	return b_str;
}

function convertBinaryStringToUint8Array(bStr: string) {
	var i, len = bStr.length, u8_array = new Uint8Array(len);
	for (i = 0; i < len; i++) {
		u8_array[i] = bStr.charCodeAt(i);
	}
	return u8_array;
}