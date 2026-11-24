#!/usr/bin/env node
/**
 * @module secret-triage-mcp
 * @path ~/.dsh/ventures/mcp-secret-triage/server.mjs
 * @description MCP server（stdio / JSON-RPC 2.0）：把「密钥扫描器报告」按语境分诊成"真需处理"与"可排除"。
 *   零依赖、纯本地、不联网。面向 agent 调用：输入一份 gitleaks/SARIF/文本报告，输出逐条判定与理由。
 * @zone action
 * @phase emerging
 * @tier Tier3-venture
 * @skill mcp_initialize — 处理 initialize / tools/list / tools/call / ping 四个方法，未知方法返回 JSON-RPC error。
 * @skill triage_by_context — 仅凭**路径与规则名**判定语境（tests/spec/fixtures、rules/signatures/patterns、
 *   docs/md、lib/dist/build、detector 自身、知识库快照），不读取目标仓库文件（MCP 客户端可能不共享文件系统）。
 * @skill parse_report — 支持 gitleaks JSON / SARIF / 含 `路径:行号` 的文本三种输入。
 * @rule real_exit_code P1 — 进程不因业务结果改变退出码；错误通过 JSON-RPC error 或结果字段返回
 * @rule no_network P0 — 服务本身不做任何网络请求（MCP 客户端可能在被审计的环境里运行）
 * @rule path_only_classification P0 — 只依据路径与规则名判定，**不得声称读过文件内容**；若需要内容判定，
 *   必须由调用方通过 `fileContents` 显式提供，并在结果里标注 `usedFileContents:true`
 * @rule unknown_method_is_error P1 — 未知方法必须返回 error（-32601），不得静默返回空结果
 * @depends node:process
 * @error JsonParseError — 收到非法 JSON 行 → 返回 -32700
 * @metric 每次 tools/call 返回 measures{total,real,triaged,buckets}
 * @memory 2026-11-24 路径 A：Ithiel 30 天实验里**唯一干净且持久**的分发成果是 MCP registry 上架；agent 是天然客户
 *
 * 用法：
 *   node server.mjs            # stdio 模式（供 MCP 客户端拉起）
 *   node server.mjs --selftest # 自检：跑一遍协议与分诊
 */

import { createInterface } from 'node:readline'

const SERVER_INFO = { name: 'secret-triage', version: '0.1.0' }
const PROTOCOL_VERSION = '2024-11-05'

/** 路径语境规则（顺序敏感：先具体后笼统）。 */
const CONTEXT_RULES = [
  { bucket: 'fixture', test: (p) => /(^|\/)(tests?|__tests__|spec|specs|fixtures?|testdata|e2e)(\/|$)/.test(p) || /(_test\.go|\.spec\.[jt]sx?|\.test\.[jt]sx?|(^|\/)test_.*\.py)$/.test(p) },
  { bucket: 'rulefile', test: (p) => /(gitleaks\.toml|\.gitleaks|detect-secrets|secrets?[-_]?baseline|secret-patterns?)/.test(p) || /(^|\/)(rules|signatures|patterns|detectors)(\/|$)/.test(p) || /(regex|regexes|patterns?|signatures?|rules?)\.[a-z]+$/.test(p) },
  { bucket: 'doc', test: (p) => /\.(md|mdx|txt)$/.test(p) || p.includes('/docs/') },
  { bucket: 'artifact', test: (p) => /(^|\/)(lib|dist|build|out|chunks|vendor)(\/|$)/.test(p) || /\.min\.(js|css)$/.test(p) },
  { bucket: 'detector', test: (p) => /(verify|check|scan|audit|guard|lint)[-_\w]*secret|secret[-_]?(scan|check|detect|guard)/.test(p) },
  { bucket: 'snapshot', test: (p) => /\.(json|ndjson|jsonl)$/.test(p) && /(store|snapshot|corpus|knowledge|okf|memory)/.test(p) },
]

/**
 * 按路径与规则名判定语境。
 * @param {string} rel 相对路径
 * @param {string|null} rule 规则名
 * @returns {string} 桶名：fixture|rulefile|doc|artifact|detector|snapshot|real
 */
export function classify(rel, rule) {
  const p = String(rel).toLowerCase()
  for (const r of CONTEXT_RULES) if (r.test(p)) return r.bucket
  // 规则名本身泄露语境（如 rule 叫 "test-fixture-token"）
  if (rule && /(test|fixture|example|dummy|sample)/i.test(rule)) return 'fixture'
  return 'real'
}

/**
 * 解析扫描器报告（gitleaks JSON / SARIF / 文本）。
 * @param {string} raw 报告原文
 * @returns {Array<{file:string,line:number|null,rule:string|null}>}
 */
export function parseReport(raw) {
  const text = String(raw ?? '')
  let parsed = null
  try { parsed = JSON.parse(text) } catch { parsed = null }
  if (Array.isArray(parsed)) {
    const out = []
    for (const it of parsed) {
      const file = it?.File ?? it?.file ?? it?.path
      if (!file) continue
      out.push({ file: String(file), line: Number(it?.StartLine ?? it?.line ?? 0) || null, rule: it?.RuleID ?? it?.rule ?? null })
    }
    if (out.length > 0) return out
  }
  if (parsed && Array.isArray(parsed.runs)) {
    const out = []
    for (const run of parsed.runs) for (const res of run?.results ?? []) for (const loc of res?.locations ?? []) {
      const uri = loc?.physicalLocation?.artifactLocation?.uri
      if (!uri) continue
      out.push({ file: String(uri).replace(/^file:\/\//, ''), line: Number(loc?.physicalLocation?.region?.startLine) || null, rule: res?.ruleId ?? null })
    }
    if (out.length > 0) return out
  }
  const out = []
  const seen = new Set()
  for (const line of text.split('\n')) {
    const m = line.match(/([\w./@-]+\.[A-Za-z0-9]+):(\d+)/)
    if (!m) continue
    const key = `${m[1]}:${m[2]}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ file: m[1], line: Number(m[2]), rule: null })
  }
  return out
}

/**
 * 分诊一份报告。
 * @param {string} raw 报告原文
 * @param {Record<string,string>|undefined} fileContents 可选的"路径→行文本"映射（调用方提供才用）
 * @returns {object} 结构化结果
 */
export function triageReport(raw, fileContents) {
  const findings = parseReport(raw)
  const buckets = { fixture: [], rulefile: [], doc: [], artifact: [], detector: [], snapshot: [] }
  const real = []
  let usedFileContents = false
  for (const f of findings) {
    const rel = String(f.file).replace(/^\.\//, '')
    let bucket = classify(rel, f.rule)
    // 只有调用方显式给了内容，才用内容辅助判定（并在结果里标注）
    if (fileContents && typeof fileContents[rel] === 'string') {
      usedFileContents = true
      if (/\b(fake|dummy|example|placeholder|redact|test[_-]?(?:key|token|secret))\b/i.test(fileContents[rel]) && bucket === 'real') bucket = 'fixture'
    }
    const label = `${rel}${f.line ? `:${f.line}` : ''}${f.rule ? ` [${f.rule}]` : ''}`
    if (bucket === 'real') real.push(label)
    else buckets[bucket].push(label)
  }
  const triaged = Object.values(buckets).reduce((s, a) => s + a.length, 0)
  return {
    measures: { total: findings.length, real: real.length, triaged, buckets: Object.fromEntries(Object.entries(buckets).map(([k, v]) => [k, v.length])) },
    usedFileContents,
    real,
    excluded: buckets,
    note: '仅依据路径与规则名判定；usedFileContents=false 表示未读取任何文件内容。',
  }
}

/** MCP 工具清单。 */
const TOOLS = [{
  name: 'triage_secret_report',
  description: '对密钥扫描器报告做语境分诊：区分"真需处理"与"测试夹具/规则文件/文档/构建产物/检测器自身/知识库快照"。零依赖、纯本地、不联网。',
  inputSchema: {
    type: 'object',
    properties: {
      report: { type: 'string', description: '扫描器报告原文（gitleaks JSON / SARIF / 含 路径:行号 的文本）' },
      fileContents: { type: 'object', description: '可选：路径→该行文本的映射，仅用于内容辅助判定', additionalProperties: { type: 'string' } },
    },
    required: ['report'],
  },
}]

/** 处理一条 JSON-RPC 消息，返回响应对象（通知返回 null）。 */
export function handleMessage(msg) {
  if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    return { jsonrpc: '2.0', id: msg?.id ?? null, error: { code: -32600, message: 'Invalid Request' } }
  }
  const { id, method, params } = msg
  const isNotification = id === undefined || id === null
  if (method === 'initialize') {
    return { jsonrpc: '2.0', id, result: { protocolVersion: PROTOCOL_VERSION, serverInfo: SERVER_INFO, capabilities: { tools: {} } } }
  }
  if (method === 'notifications/initialized' || method === 'initialized') return null
  if (method === 'ping') return { jsonrpc: '2.0', id, result: {} }
  if (method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: TOOLS } }
  if (method === 'tools/call') {
    const name = params?.name
    if (name !== 'triage_secret_report') {
      return { jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown tool: ${String(name)}` } }
    }
    const args = params?.arguments ?? {}
    if (typeof args.report !== 'string' || args.report.trim() === '') {
      return { jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: '缺少 report 参数（扫描器报告原文）' }] } }
    }
    const out = triageReport(args.report, args.fileContents)
    return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] } }
  }
  if (isNotification) return null
  return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } }
}

if (process.argv.includes('--selftest')) {
  let bad = 0
  const ok = (name, cond, detail) => { if (!cond) { bad += 1; console.log(`  FAIL ${name}${detail ? ` -> ${detail}` : ''}`) } else console.log(`  OK ${name}`) }
  const init = handleMessage({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })
  ok('initialize 返回协议版本', init.result?.protocolVersion === PROTOCOL_VERSION)
  const list = handleMessage({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
  ok('tools/list 暴露 1 个工具', list.result?.tools?.length === 1)
  const unknown = handleMessage({ jsonrpc: '2.0', id: 3, method: 'nope' })
  ok('未知方法返回 -32601', unknown.error?.code === -32601)
  const badReq = handleMessage({ id: 4, method: 'x' })
  ok('非法请求返回 -32600', badReq.error?.code === -32600)
  const call = handleMessage({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'triage_secret_report', arguments: { report: JSON.stringify([
    { File: 'tests/a.spec.ts', StartLine: 3, RuleID: 'aws' },
    { File: 'rules/aws.yml', StartLine: 16, RuleID: 'aws' },
    { File: 'src/leak.js', StartLine: 2, RuleID: 'github-pat' },
  ]) } } })
  const parsed = JSON.parse(call.result.content[0].text)
  ok('分诊：1 真 2 排除', parsed.measures.real === 1 && parsed.measures.triaged === 2, JSON.stringify(parsed.measures))
  ok('声明未读文件内容', parsed.usedFileContents === false)
  const empty = handleMessage({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'triage_secret_report', arguments: { report: 'no findings' } } })
  ok('空报告返回 0 条而非报错', JSON.parse(empty.result.content[0].text).measures.total === 0)
  const missing = handleMessage({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'triage_secret_report', arguments: {} } })
  ok('缺 report 参数 → isError', missing.result?.isError === true)
  console.log(`secret-triage-mcp --selftest: ${bad === 0 ? 'PASS' : `FAIL（${bad} 处）`}`)
  process.exit(bad === 0 ? 0 : 1)
}

const rl = createInterface({ input: process.stdin })
rl.on('line', (line) => {
  const trimmed = line.trim()
  if (trimmed === '') return
  let msg
  try { msg = JSON.parse(trimmed) } catch {
    process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })}\n`)
    return
  }
  const res = handleMessage(msg)
  if (res !== null) process.stdout.write(`${JSON.stringify(res)}\n`)
})
