// Type definitions for ecc-tools 1.0.4
// Project: ecc-tools
// Definitions by: Justin Laue <https://github.com/fp-x>

// import promise = require('@types/es6-promise');
// declare class Promise {
//   // some stuff here
// }


// export function privateKey(): any;
// export function publicKey(privateKey: Buffer, useCompressedKeys: boolean): Buffer;
// export function decrypt(cipher: string, privateKey: string, algorithm?: string): any; // change to Promise?
// export function encrypt(plaintext: string, publicKey: string, algorithm?: string): any; // change to Promise?

declare class ecc {
	public static privateKey(): any;
	public static publicKey(privateKey: Buffer, useCompressedKeys?: boolean): Buffer;
	public static decrypt(cipher: string, privateKey: string, algorithm?: string): any; // change to Promise?
	public static encrypt(plaintext: string, publicKey: string, algorithm?: string): any; // change to Promise?
	public static sha256ripemd160(msg: Buffer): Buffer;
	public static sha256sha256(msg: Buffer): Buffer;
	public static cipher(plaintext: string, key: Buffer, iv: string, algorithm?: string): any;
	public static decipher(ciphertext: string, key: Buffer, iv: string, algorithm?: string): any;

}

export = ecc;
// export as namespace ecc;
