// Type definitions for ecc-tools 1.0.4
// Project: ecc-tools
// Definitions by: Justin Laue <https://github.com/fp-x>

// import promise = require('@types/es6-promise');
// declare class Promise {
//   // some stuff here
// }

export as namespace ecctoolkit;

export function privateKey(): any;
export function publicKey(privateKey: Buffer, useCompressedKeys: boolean): Buffer;
export function decrypt(cipher: string, privateKey: string, algorithm: string): any; // change to Promise?
export function encrypt(plaintext: string, publicKey: string, algorithm: string): any; // change to Promise?
