import { Command } from 'commander';
import { handleIngest } from './commands/ingest.js';
import { handleInvestigate } from './commands/investigate.js';
import { handleStatus } from './commands/status.js';
import {
  handleCaseShow,
  handleEvidenceShow,
  handleEntityShow,
  handleGraphShow,
  handleExplain,
} from './commands/drilldown.js';

export function createAegisCliProgram(): Command {
  const program = new Command();

  program
    .name('aegis')
    .description('AEGIS Cyber Threat Intelligence Platform CLI')
    .version('0.1.0');

  program
    .command('investigate')
    .description('Run end-to-end automated investigation over darknet feeds and OSINT sources')
    .requiredOption('-t, --target <target>', 'Target actor identifier or alias')
    .option('--plane <plane>', 'Execution plane (lab|real)', 'real')
    .action((opts) => {
      const plane = opts.plane === 'lab' ? 'CONTROLLED_LAB_PLANE' : 'REAL_WORLD_PLANE';
      const res = handleInvestigate(opts.target, plane);
      console.log(JSON.stringify(res, null, 2));
    });

  // Case command & subcommands
  const caseCmd = program.command('case').description('Case management commands');
  caseCmd
    .command('show <caseId>')
    .description('Display detailed investigation case overview')
    .action((caseId) => {
      const res = handleCaseShow(caseId);
      console.log(res.banner);
    });

  // Evidence command & subcommands
  const evidenceCmd = program.command('evidence').description('Evidence inspection commands');
  evidenceCmd
    .command('show <evidenceId>')
    .description('Display raw evidence record, payload, and cryptographic digest')
    .action((evidenceId) => {
      const res = handleEvidenceShow(evidenceId);
      console.log(JSON.stringify(res, null, 2));
    });

  // Entity command & subcommands
  const entityCmd = program.command('entity').description('Entity graph inspection commands');
  entityCmd
    .command('show <entityValue>')
    .description('Display entity profile and linked graph nodes')
    .action((entityValue) => {
      const res = handleEntityShow(entityValue);
      console.log(JSON.stringify(res, null, 2));
    });

  // Graph command
  program
    .command('graph <target>')
    .description('Render ASCII relationship graph connecting darknet forums and OSINT sources')
    .action((target) => {
      const res = handleGraphShow(target);
      console.log(res.asciiGraph);
    });

  // Explain command
  program
    .command('explain <candidateId>')
    .description('Deep-dive into attribution lead scoring factors and evidence citations')
    .action((candidateId) => {
      const res = handleExplain(candidateId);
      console.log(JSON.stringify(res, null, 2));
    });

  program
    .command('ingest')
    .description('Ingest raw payload into immutable EvidenceRecord')
    .requiredOption('-t, --type <type>', 'Source type (osint|darkweb|telemetry|synthetic)')
    .requiredOption('-u, --uri <uri>', 'Source URI')
    .requiredOption('-p, --payload <payload>', 'Raw payload string/JSON')
    .action((opts) => {
      const res = handleIngest(opts.type, opts.uri, opts.payload);
      console.log(JSON.stringify(res, null, 2));
    });

  program
    .command('status')
    .description('Check WolverineDB and Wolverine Runtime self-protection status')
    .action(() => {
      const status = handleStatus();
      console.log(JSON.stringify(status, null, 2));
    });

  return program;
}
