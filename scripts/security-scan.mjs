import fs from "node:fs";
import path from "node:path";
const root = path.resolve("src");
const files = fs.readdirSync(root).filter((f) => f.endsWith(".ts"));
const forbidden = [/node:child_process/, /from\s+["']child_process["']/, /\bfetch\s*\(/, /\bhttps?:\/\//, /node:fs/, /\beval\s*\(/, /new\s+Function\s*\(/, /\bspawn\s*\(/, /\bexec\s*\(/, /\bWebSocket\b/, /\bnet\.connect\s*\(/];
const hits=[];
for (const file of files) { const text=fs.readFileSync(path.join(root,file),"utf8"); text.split(/\r?\n/).forEach((line,i)=>forbidden.forEach((re)=>{if(re.test(line))hits.push(`${file}:${i+1}: ${re}`);})); }
if(hits.length){console.error(hits.join("\n"));process.exit(1);} console.log(`security scan PASS: ${files.length} runtime source files, 0 forbidden network/filesystem/process/dynamic-eval surfaces`);
