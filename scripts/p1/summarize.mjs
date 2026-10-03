// 绑定原件、去敏审计、契约和工具哈希；不训练、推理或改写标签。已存在的报告只允许 --check。
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const check = process.argv.length === 3 && process.argv[2] === '--check';
if (process.argv.length > 2 && !check) throw new Error('Only --check is accepted');
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const digest = (file) => hash(readFileSync(join(root, file)));
const read = (file) => JSON.parse(readFileSync(join(root, file), 'utf8'));
const captureRoot = 'https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/';
const scenarios = [
  { stem: 'hakai', id: 'CTU-IoT-Malware-Capture-8-1', pcap: '2018-07-31-15-15-09-192.168.100.113.pcap', labelRevision: '2019-12-25' },
  { stem: 'muhstik', id: 'CTU-IoT-Malware-Capture-3-1', pcap: '2018-05-21_capture.pcap', labelRevision: '2019-12-25' },
  { stem: 'mirai', id: 'CTU-IoT-Malware-Capture-34-1', pcap: '2018-12-21-15-50-14-192.168.1.195.pcap', labelRevision: '2023-12-12' },
];
const reports = scenarios.map(({ stem }) => read(`artifacts/p1/${stem}-v1-audit.json`));
const windows = read('artifacts/p1/windows-preflight.json');
const windowsPost = read('artifacts/p1/windows-postflight.json');
const zenodo = read('data/raw/p1/iot23/zenodo-record.json');
if (zenodo.metadata.version !== '1.0.0' || zenodo.metadata.license.id !== 'cc-by-4.0') throw new Error('Source licence/version changed');
if (reports[0].sampleJoinGate !== 'passed_sample_only' || reports[1].sampleJoinGate !== 'passed_sample_only') throw new Error('Research sample gate changed');
if (windows.canary.startup.started || windows.canary.startup.nativeErrorCode !== 4551 || windows.npcap.wpcapDllPresent) throw new Error('Platform findings changed; review stage conclusions');
const originalWindowsWorktree = [
  '?? scripts/phase2_finish_cic2017.py', '?? scripts/phase2_prepare_cic2017.py', '?? src/cyber_training/phase2/',
  '?? tests/test_phase2_baseline.py', '?? tests/test_phase2_labels.py', '?? tests/test_phase2_review.py',
  '?? tests/test_phase2_split.py', '?? tests/test_phase2_transfer.py',
];
if (windowsPost.branch !== 'training/windows-cuda' || !windowsPost.head.startsWith('9378f02') ||
    JSON.stringify([...windowsPost.worktree].sort()) !== JSON.stringify([...originalWindowsWorktree].sort())) throw new Error('Windows baseline/worktree changed');
const counts = (values) => values.reduce((out, value) => { out[value] = (out[value] ?? 0) + 1; return out; }, {});
const artifact = (file) => ({ path: file, bytes: statSync(join(root, file)).size, sha256: digest(file) });
const codePaths = [
  'sensor/go.mod', 'sensor/go.sum', 'sensor/internal/capture/file.go', 'sensor/internal/packet/parse.go',
  'sensor/internal/probe/join.go', 'sensor/internal/probe/join_test.go', 'sensor/cmd/p1audit/main.go',
  'sensor/cmd/p1canary/main.go', 'sensor/cmd/p1canary/main_test.go',
  'scripts/p1/windows-preflight.ps1', 'scripts/p1/summarize.mjs',
];
const codeFiles = codePaths.map(artifact);
const combine = (files) => hash(files.map((file) => `${file.path}\0${file.sha256}\n`).join(''));
const contractFiles = readdirSync(join(root, 'docs/contracts'), { recursive: true })
  .filter((name) => name.endsWith('.json')).sort().map((name) => artifact(`docs/contracts/${name}`));
contractFiles.push(artifact('docs/检测与处置契约.md'));
const config = {
  countPerScenario: 30, timestampToleranceUs: 1000, offloadScreenMTU: 1500,
  positiveAndNegativeSampling: '10 TCP/UDP per class, then 10 boundary samples, stable SHA-256 order',
  protocolScope: ['tcp', 'udp'], labelScope: 'final_only', rawBudgetBytes: 2 * 1024 ** 3,
  packetOrder: 'global timestamp order for reference calculation only; not a v5 causal extractor',
};
const provenance = {
  version: 'p1-provenance-v1', codeSha256: combine(codeFiles), codeFiles,
  applicationBaseline: execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
  windowsTrainingBaseline: windowsPost.head,
  contractsSha256: combine(contractFiles), contractFiles, config, configSha256: hash(JSON.stringify(config)),
  labelPolicySha256: digest('docs/p1/label-policy.md'),
  observedAt: windows.observedAt, environment: reports[0].environment,
};
const rawFiles = scenarios.flatMap((scenario, i) => {
  const report = reports[i];
  if (report.scenario !== scenario.id || !report.researchOnly) throw new Error('Unexpected audit scope');
  if (report.contractProfileSha256 !== digest('docs/contracts/feature-profile.json')) throw new Error('Stale contract');
  return [['pcap', report.pcapSha256, report.pcapBytes], ['conn.log.labeled', report.labelSha256, report.labelBytes]].map(([suffix, expected, size]) => {
    const file = `data/raw/p1/iot23/${scenario.stem}${suffix === 'pcap' ? '.pcap' : '-conn.log.labeled'}`;
    const actual = artifact(file);
    if (actual.sha256 !== expected || actual.bytes !== size) throw new Error('Raw file differs from audit');
    return { scenario: scenario.id, ...actual, originalUrl: `${captureRoot}${scenario.id}/${suffix === 'pcap' ? scenario.pcap : 'bro/conn.log.labeled'}` };
  });
});
const rawBytes = rawFiles.reduce((sum, file) => sum + file.bytes, 0);
if (rawBytes > config.rawBudgetBytes) throw new Error('P1 raw budget exceeded');
if (windows.canary.sha256 !== digest('sensor/bin/p1canary.exe')) throw new Error('Windows binary hash mismatch');

const sourceManifest = {
  version: 'p1-source-manifest-v1', provenance,
  candidateSourceCount: 2, rawBudgetBytes: config.rawBudgetBytes, rawBytes, files: rawFiles,
  sources: [
    {
      id: 'iot23', publisher: 'Stratosphere Laboratory', doi: zenodo.doi, version: zenodo.metadata.version,
      citation: 'Garcia, Parmisano and Erquiaga (2020). IoT-23. doi:10.5281/zenodo.4743746',
      licence: 'CC-BY-4.0 in versioned Zenodo record; mirror master README links CC-BY-2.0',
      licenceEvidence: artifact('data/raw/p1/iot23/zenodo-record.json'),
      licenceReview: 'Dataset-level public grant; legacy per-capture README permission wording retained as a discrepancy. Only documented IoT-23 PCAP/labels used; no malware binaries.',
      mirrorRevisionIsFrozenRelease: false,
      role: 'public final-flow research; IoT benign labels do not prove desktop benign coverage',
    },
    {
      id: 'cicids2017-cns2022', status: 'blocked_raw_acquisition',
      sourceUrl: 'https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/',
      metadataEvidence: artifact('artifacts/p1/cic-corrected-index.html'),
      correctedTableArchiveAdvertisedSize: '328M', correctedTableDownloaded: false,
      pcapEndpoint: 'https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/',
      attemptedReadExitCode: 6, reason: 'PCAP endpoint DNS resolution failed; corrected CSV is not raw packets',
      licenceReviewedForLocalUse: false,
      nextExperiment: 'Restore publisher PCAP access and verify a complete bounded scene before downloading corrected tables',
    },
  ],
  remoteReuse: { source: 'existing Windows Muhstik pilot', pcapAndLabelHashesMatch: true, transferInterrupted: true, publisherFallbackHashesMatch: true },
  holdoutEvaluated: false, trainingExecuted: false,
};
const sampleAudit = {
  version: 'p1-sample-join-bundle-v1', provenance,
  totalSampled: reports.reduce((sum, report) => sum + report.samples.length, 0),
  result: 'two scenarios pass sampled association; Mirai DDoS has ambiguous/inconsistent publisher connection evidence',
  scenarios: reports,
  limitation: 'No full join, prefix label certification, model input export or final test evaluation',
};
const coverage = {
  version: 'p1-coverage-matrix-v1', provenance,
  dataExitStatus: 'failed', researchSampleStatus: 'passed', earlyAutoCapability: false,
  captures: reports.map((report) => ({
    scenario: report.scenario, labelConnections: report.labelConnections,
    publisherLabelDistribution: report.publisherLabelDistribution,
    publisherZeroPacketCounts: report.publisherZeroPacketCounts,
    sampledJoinCounts: counts(report.samples.map((sample) => sample.joinStatus)),
    sampledClassCounts: { attack: 0, benign: 0, unknown: 0, ...counts(report.samples.map((sample) => sample.class)) },
    sampledDirections: counts(report.samples.map((sample) => sample.direction)),
    sampledTargetMetadataConstructible: report.samples.filter((sample) => sample.targetMetadataConstructible).length,
    labelScope: 'final_only', historicalCaptureDrops: null,
  })),
  capabilityDecisions: [
    { family: 'connection_abuse', evidence: 'horizontal scans in independent captures 3-1 and 34-1', status: 'alert_research_only', reason: 'Different peer targets cannot be combined into one peer_service block; no demonstrated scan coverage by narrow rules' },
    { family: 'sustained_flood', evidence: 'DDoS in 34-1', status: 'blocked_label_association', reason: 'Sampled publisher packet counters are zero and time windows overlap; independent flood activity and onset still required' },
    { family: 'C&C', evidence: 'publisher labels in captures 8-1, 3-1 and 34-1', status: 'final_research_candidate', reason: 'Independent capture activities available; no attack onset or measured separability from legitimate periodic services; not promoted to connection_abuse' },
  ],
  budgetForP2: { maximumSources: 2, parentConnectionsPerSource: 100000, snapshotsPerConnectionMustBeGrouped: true, finalCaptureNotAssigned: true },
};
const platform = {
  version: 'p1-platform-capability-probe-v1', provenance, status: 'blocked',
  windows: {
    target: 'win-dev', evidence: windows, preflightExitCode: 2,
    codeIntegrityEvents: windowsPost.codeIntegrityEvents,
    actionGate: 'failed_program_start_and_missing_capture_dependency',
    postProbe: { evidence: artifact('artifacts/p1/windows-postflight.json'), observedAt: windowsPost.observedAt,
      ownedTestRulesRemaining: windowsPost.ownedTestRulesRemaining, firewallService: windowsPost.firewallService,
      sshService: windowsPost.sshService, trainingWorktreeUnchanged: true },
    testsNotExecuted: ['network-layer canary isolation', 'narrow rule namespace and management protection', 'new connection blocking', 'existing connection blocking', '30s expiry', 'process exit recovery', 'control-plane loss recovery', 'host reboot recovery'],
    nextExperiment: 'Use a legitimately trusted signed build accepted by current application control, then verify licensed Npcap without weakening system policy',
  },
  macOS: {
    status: 'blocked_missing_isolated_asset_scope', os: { version: '27.2', build: '26B5091g' },
    captureDependency: { tool: 'Apple tcpdump 4.99.1 / Apple 161', libpcap: '1.10.1', liveCaptureVerified: false },
    bpf0Owner: 'root', bpf0Mode: '0600', pfctlPresent: true,
    firewallModified: false, actionEffectVerified: false, recoveryVerified: false,
  },
  autoCapabilityGranted: false, restartPerformed: false,
};
const outputs = new Map([
  ['source-manifest.json', sourceManifest], ['sample-join-audit.json', sampleAudit],
  ['coverage-matrix.json', coverage], ['platform-capability-probe.json', platform],
]);
const outDir = join(root, 'docs/p1');
for (const name of outputs.keys()) if (!check && existsSync(join(outDir, name))) throw new Error(`Report already exists: ${name}`);
mkdirSync(outDir, { recursive: true });
for (const [name, value] of outputs) {
  const path = join(outDir, name);
  if (check) {
    if (JSON.stringify(JSON.parse(readFileSync(path, 'utf8'))) !== JSON.stringify(value)) throw new Error(`Report stale: ${relative(root, path)}`);
  } else { writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 }); }
}
console.log(JSON.stringify({ checked: check, reports: outputs.size, rawBytes, sampled: sampleAudit.totalSampled, p1: 'blocked' }));
