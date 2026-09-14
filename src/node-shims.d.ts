declare module "node:test" { const test: (name: string, fn: () => void | Promise<void>) => void; export default test; }
declare module "node:assert/strict" { const assert: any; export default assert; }
declare module "node:readline" { export function createInterface(options: any): AsyncIterable<string> & { close(): void }; }
declare const process: any;
declare const require: any;
declare const module: any;
