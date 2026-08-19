import fs from 'node:fs';
import path from 'node:path';
// @ts-ignore
import solc from 'solc';

export interface CompilationResult {
  abi: any[];
  bytecode: `0x${string}`;
}

export function compileWolverineTrustRegistry(): CompilationResult {
  const contractPath = path.resolve(process.cwd(), 'blockchain', 'contracts', 'WolverineTrustRegistry.sol');
  if (!fs.existsSync(contractPath)) {
    throw new Error(`Contract file not found at ${contractPath}`);
  }

  const source = fs.readFileSync(contractPath, 'utf8');

  const input = {
    language: 'Solidity',
    sources: {
      'WolverineTrustRegistry.sol': {
        content: source,
      },
    },
    settings: {
      evmVersion: 'paris',
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 200,
      },
      outputSelection: {
        '*': {
          '*': ['abi', 'evm.bytecode.object'],
        },
      },
    },
  };

  const output = JSON.parse(solc.compile(JSON.stringify(input)));

  if (output.errors) {
    const fatalErrors = output.errors.filter((err: any) => err.severity === 'error');
    if (fatalErrors.length > 0) {
      throw new Error(`Solidity compilation failed:\n${fatalErrors.map((e: any) => e.formattedMessage).join('\n')}`);
    }
  }

  const contractObj = output.contracts['WolverineTrustRegistry.sol']['WolverineTrustRegistry'];
  if (!contractObj) {
    throw new Error('Contract WolverineTrustRegistry not found in compilation output');
  }

  const bytecode = `0x${contractObj.evm.bytecode.object}` as `0x${string}`;
  const abi = contractObj.abi;

  return {
    abi,
    bytecode,
  };
}
