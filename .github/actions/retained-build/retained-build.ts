import { execFileSync } from 'node:child_process';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export interface Evidence {
  schema: number;
  repository: string;
  workflow: string;
  run_id: number;
  run_attempt: number;
  head_sha: string;
  built_sha: string;
  tree: string;
}
export interface Run {
  id: number;
  run_attempt: number;
  head_sha: string;
  head_branch: string;
  head_repository: { full_name: string };
  path: string;
  event: string;
  status: string;
  conclusion: string;
  pull_requests: { number: number; base: { ref: string; repo: { id: number } }; head: { sha: string; repo: { id: number } } }[];
}
const sha = /^[a-f0-9]{40}$/;
const text = (args: string[]) => execFileSync(args[0], args.slice(1), { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }).trim();
const api = (path: string): any => JSON.parse(text(['gh', 'api', path]));

export function validate(evidence: Evidence, run: Run, repository: string, workflow: string, tree: string): void {
  if (run.status !== 'completed' || run.conclusion !== 'success'
      || run.head_repository?.full_name !== repository || run.path !== `.github/workflows/${workflow}`
      || !['pull_request', 'workflow_dispatch', 'push'].includes(run.event)) throw new Error('Untrusted build run');
  if (run.event === 'pull_request') {
    if (!run.pull_requests.some(pr => pr.base.ref === 'staging' && pr.head.sha === run.head_sha
      && pr.base.repo.id === pr.head.repo.id)) throw new Error('Build did not validate a same-repository staging PR');
  } else if (run.head_branch !== 'staging') throw new Error('Build did not run on staging');
  if (evidence.schema !== 1 || evidence.repository !== repository || evidence.workflow !== workflow
      || evidence.run_id !== run.id || evidence.run_attempt !== run.run_attempt || evidence.head_sha !== run.head_sha
      || !sha.test(evidence.built_sha) || !sha.test(evidence.tree) || evidence.tree !== tree) {
    throw new Error('Retained build does not match this repository, run attempt and complete source tree');
  }
}

export function mustReuse(eventName: string, event: any, ref: string, repository: string): boolean {
  if (eventName === 'pull_request' && event.pull_request.base.ref === 'main') {
    const pr = event.pull_request;
    if (pr.head.repo.full_name !== repository) throw new Error('Production promotion cannot come from a fork');
    // A hotfix has a new tree and must pass the complete build checks first.
    if (pr.head.ref.startsWith('hotfix/')) return false;
    if (pr.head.ref !== 'staging') throw new Error('Production promotion must come from staging');
    return true;
  }
  return ref === 'refs/heads/main';
}

export function main(): void {
  const env = process.env;
  const repository = env.GITHUB_REPOSITORY!;
  const workflow = env.RETAINED_BUILD_WORKFLOW!;
  if (!/^[\w.-]+\.ya?ml$/.test(workflow)) throw new Error('Expected a workflow filename');
  const event = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH!, 'utf8'));
  const builtSha = text(['git', 'rev-parse', 'HEAD']);
  const tree = text(['git', 'rev-parse', 'HEAD^{tree}']);
  const output = (key: string, value: string) => appendFileSync(env.GITHUB_OUTPUT!, `${key}=${value}\n`);
  const runId = Number(env.GITHUB_RUN_ID);
  if (env.RETAINED_BUILD_MODE === 'record') {
    const run: Run = api(`repos/${repository}/actions/runs/${runId}`);
    const evidence: Evidence = { schema: 1, repository, workflow, run_id: runId,
      run_attempt: Number(env.GITHUB_RUN_ATTEMPT), head_sha: run.head_sha, built_sha: builtSha, tree };
    const dir = join(env.RUNNER_TEMP!, 'retained-build');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'build-result.json'), JSON.stringify(evidence, null, 2) + '\n');
    return;
  }
  if (env.RETAINED_BUILD_MODE !== 'resolve') throw new Error('Expected resolve or record mode');
  const required = mustReuse(env.GITHUB_EVENT_NAME!, event, env.GITHUB_REF!, repository);
  const staging = env.GITHUB_REF === 'refs/heads/staging'
    || (env.GITHUB_EVENT_NAME === 'pull_request' && event.pull_request.base.ref === 'staging');
  if (!required && !staging) {
    output('build-required', 'true');
    return;
  }
  // Include the full tree, including workflow files and lockfiles. A merge commit
  // changes the commit id even when every source byte is unchanged.
  for (let page = 1; page <= 10; page++) {
    const runs: Run[] = api(`repos/${repository}/actions/workflows/${workflow}/runs?status=success&per_page=100&page=${page}`).workflow_runs;
    for (const run of runs) {
      if (run.id === runId || run.head_repository?.full_name !== repository
          || (run.event === 'pull_request' ? !run.pull_requests.some(pr => pr.base.ref === 'staging') : run.head_branch !== 'staging')) continue;
      const artifacts = api(`repos/${repository}/actions/runs/${run.id}/artifacts?per_page=100`).artifacts;
      const name = `retained-build-${workflow}-${run.run_attempt}`;
      if (!artifacts.some((a: any) => a.name === name && !a.expired)) continue;
      const dir = mkdtempSync(join(env.RUNNER_TEMP!, 'retained-source-'));
      try {
        text(['gh', 'run', 'download', String(run.id), '--repo', repository, '--name', name, '--dir', dir]);
        const evidence: Evidence = JSON.parse(readFileSync(join(dir, 'build-result.json'), 'utf8'));
        try { validate(evidence, run, repository, workflow, tree); } catch { continue; }
        const commit = api(`repos/${repository}/git/commits/${evidence.built_sha}`);
        if (commit.tree.sha !== tree) throw new Error('Build commit tree does not match retained evidence');
        output('build-required', 'false');
        output('run-id', String(run.id));
        appendFileSync(env.GITHUB_STEP_SUMMARY!, `Reusing [staging build ${run.id}](https://github.com/${repository}/actions/runs/${run.id}) for tree \`${tree}\`. No compilation.\n`);
        return;
      } finally { rmSync(dir, { recursive: true, force: true }); }
    }
    if (runs.length < 100) break;
  }
  if (!required) {
    output('build-required', 'true');
    return;
  }
  throw new Error('No successful retained staging build matches this complete tree. Build and validate staging first; production never rebuilds as a fallback.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
