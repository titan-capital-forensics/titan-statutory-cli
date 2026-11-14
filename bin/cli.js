#!/usr/bin/env node
const { execSync } = require('child_process');
const path = require('path');

const pythonScript = path.join(__dirname, '..', 'titan_statutory', 'cli.py');

function printUsage() {
  console.log('Usage: titan-statutory <command> [options]');
  console.log('Commands:');
  console.log('  check-cbam    Check EU CBAM applicability');
  console.log('  check-179d    Check IRS Section 179D readiness');
  console.log('  check-einvoice Check UAE QFZP/GDPR applicability');
  console.log('  check-qfzp    Check UAE QFZP de-minimis cliff');
  console.log('  catalog       List available statutory tools');
}

function runPython(args) {
  try {
    const result = execSync('python3 "' + pythonScript + '" ' + args.join(' '), { encoding: 'utf8', maxBuffer: 1024 * 1024 });
    process.stdout.write(result);
    return 0;
  } catch (e) {
    if (e.code !== undefined) {
      process.stderr.write(e.stderr || '');
      return e.code;
    }
    process.stderr.write(e.message);
    return 1;
  }
}

const args = process.argv.slice(2);
if (args.length === 0) {
  printUsage();
  process.exit(1);
}

const command = args[0];
const commandArgs = args.slice(1);

const commandMap = {
  'check-cbam': true,
  'check-179d': true,
  'check-einvoice': true,
  'check-qfzp': true,
  'catalog': true
};

if (commandMap[command]) {
  runPython([command, ...commandArgs]);
} else {
  console.error(`Unknown command: ${command}`);
  printUsage();
  process.exit(1);
}
