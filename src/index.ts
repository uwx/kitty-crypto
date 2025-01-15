import { fromBytes, toBytes, type Bytes } from '@atcute/cbor';
import { Encrypter, Decrypter, type Recipient, type Identity } from '../typage/dist/index.js';
import { toString as ui8ToString } from 'uint8arrays';

function toBase58(buffer: Uint8Array) {
    return ui8ToString(buffer, 'base58btc');
}

export { generateIdentity, identityToRecipient } from '../typage/dist/index.js';

export function generatePassphrase(bits = 128) {
    return toBase58(crypto.getRandomValues(new Uint8Array(Math.max(1, (bits / 8) | 0))));
}

export async function encryptData(data: Uint8Array, passphrase?: string, target?: 'bytes'): Promise<Bytes>;
export async function encryptData(data: Uint8Array, passphrase: string | undefined, target: 'uint8array'): Promise<Uint8Array>;
export async function encryptData(data: Uint8Array, passphrase?: string, target: 'bytes' | 'uint8array' = 'bytes') {
    passphrase ??= generatePassphrase();

    const e = new Encrypter();
    e.setPassphrase(passphrase);

    return toFormat(await e.encrypt(data), target);
}

export async function decryptData(ciphertext: Bytes | Uint8Array, passphrase: string) {
    ciphertext = fromFormat(ciphertext);

    const e = new Decrypter();
    e.addPassphrase(passphrase);

    return await e.decrypt(ciphertext);
}

export async function encryptDataPublicKey(data: Uint8Array, recipients: string | Recipient | string[] | Recipient[], target?: 'bytes'): Promise<Bytes>;
export async function encryptDataPublicKey(data: Uint8Array, recipients: string | Recipient | string[] | Recipient[], target: 'uint8array'): Promise<Uint8Array>;
export async function encryptDataPublicKey(data: Uint8Array, recipients: string | Recipient | string[] | Recipient[], target: 'bytes' | 'uint8array' = 'bytes') {
    const e = new Encrypter();
    if (Array.isArray(recipients)) {
        for (const recipient of recipients) {
            e.addRecipient(recipient);
        }
    } else {
        e.addRecipient(recipients);
    }

    return toFormat(await e.encrypt(data), target);
}

export async function decryptDataPublicKey(ciphertext: Bytes | Uint8Array, identities: string | CryptoKey | Identity | string[] | CryptoKey[] | Identity[]) {
    ciphertext = fromFormat(ciphertext);

    const e = new Decrypter();
    if (Array.isArray(identities)) {
        for (const identity of identities) {
            e.addIdentity(identity);
        }
    } else {
        e.addIdentity(identities);
    }

    return await e.decrypt(ciphertext);
}

function toFormat(data: Uint8Array, target?: 'bytes'): Bytes;
function toFormat(data: Uint8Array, target: 'uint8array'): Uint8Array;
function toFormat(data: Uint8Array, target?: 'bytes' | 'uint8array'): Bytes | Uint8Array;
function toFormat(data: Uint8Array, target: 'bytes' | 'uint8array' = 'bytes') {
    if (target === 'bytes') {
        return toBytes(data);
    }
    return data;
}

function fromFormat(data: Bytes | Uint8Array) {
    if (data instanceof Uint8Array) {
        return data;
    }

    return fromBytes(data);
}