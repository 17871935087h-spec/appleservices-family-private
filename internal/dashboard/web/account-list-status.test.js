'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const vm = require('node:vm')

const appSource = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8')

function extractFunction(source, name) {
  const declaration = `function ${name}(`
  const start = source.indexOf(declaration)
  assert.notEqual(start, -1, `app.js must define ${name}`)
  const bodyStart = source.indexOf('{', start + declaration.length)
  assert.notEqual(bodyStart, -1, `${name} must have a function body`)

  let depth = 0
  let quote = ''
  let lineComment = false
  let blockComment = false
  for (let index = bodyStart; index < source.length; index += 1) {
    const current = source[index]
    const next = source[index + 1]

    if (lineComment) {
      if (current === '\n') lineComment = false
      continue
    }
    if (blockComment) {
      if (current === '*' && next === '/') {
        blockComment = false
        index += 1
      }
      continue
    }
    if (quote) {
      if (current === '\\') {
        index += 1
      } else if (current === quote) {
        quote = ''
      }
      continue
    }
    if (current === '/' && next === '/') {
      lineComment = true
      index += 1
      continue
    }
    if (current === '/' && next === '*') {
      blockComment = true
      index += 1
      continue
    }
    if (current === "'" || current === '"' || current === '`') {
      quote = current
      continue
    }
    if (current === '{') depth += 1
    if (current === '}') {
      depth -= 1
      if (depth === 0) return source.slice(start, index + 1)
    }
  }
  assert.fail(`could not find the end of ${name}`)
}

const helpers = ['workerOnline', 'canReadDeviceList', 'accountListStatus', 'shouldOfferReconnect']
  .map((name) => extractFunction(appSource, name))
  .join('\n')
const context = vm.createContext({})
vm.runInContext(helpers, context, { filename: 'app.js' })

function present(account) {
  return JSON.parse(JSON.stringify(context.accountListStatus(account)))
}

const onlineStatus = {
  state: 'online',
  running: true,
  authenticated: true,
  push_connected: true,
  verification_required: false,
}

test('requires online state and all readiness flags before marking an account online', () => {
  assert.equal(context.workerOnline(onlineStatus), true)
  for (const changes of [
    { state: 'refresh_failed' },
    { state: 'device_query_failed' },
    { running: false },
    { authenticated: false },
    { push_connected: false },
    { verification_required: true },
  ]) {
    assert.equal(context.workerOnline({ ...onlineStatus, ...changes }), false)
  }
})

test('shows refresh failure instead of a green online state', () => {
  const status = { ...onlineStatus, state: 'refresh_failed' }
  assert.deepEqual(present(status), { label: '续期失败', dot: 'waiting', online: false })
  assert.equal(context.shouldOfferReconnect(status), true)
})

test('shows device identity recovery and keeps the reconnect path available', () => {
  const status = { ...onlineStatus, state: 'device_identity_refresh_required' }
  assert.deepEqual(present(status), { label: '设备凭据需恢复', dot: 'waiting', online: false })
  assert.equal(context.shouldOfferReconnect(status), true)
  assert.equal(context.canReadDeviceList(status, true), true)
})

test('distinguishes a disconnected push channel from automatic push recovery', () => {
  const disconnected = { ...onlineStatus, push_connected: false }
  assert.deepEqual(present(disconnected), { label: '推送未连接', dot: 'waiting', online: false })
  assert.equal(context.shouldOfferReconnect(disconnected), true)

  const reconnecting = { ...disconnected, push_issue: 'reconnecting' }
  assert.deepEqual(present(reconnecting), { label: '推送重连中', dot: 'waiting', online: false })
  assert.equal(context.shouldOfferReconnect(reconnecting), false)
})

test('shows a green online dot only for a fully ready worker', () => {
  assert.deepEqual(present(onlineStatus), { label: '在线', dot: 'on', online: true })
})

test('does not claim online when readiness fields are missing', () => {
  const incomplete = { state: 'online', running: true, authenticated: true }
  assert.deepEqual(present(incomplete), { label: '状态待确认', dot: 'waiting', online: false })
})

test('keeps verification-required accounts out of the online state', () => {
  const status = { ...onlineStatus, verification_required: true, state: 'verification_required' }
  assert.deepEqual(present(status), { label: '需要验证', dot: 'waiting', online: false })
  assert.equal(context.canReadDeviceList(status, true), false)
})

test('keeps authenticated device reads available when normal online status is false', () => {
  const status = { ...onlineStatus, state: 'refresh_failed', push_connected: false }
  assert.equal(context.workerOnline(status), false)
  assert.equal(context.canReadDeviceList(status, true), true)
  assert.equal(context.canReadDeviceList(status, false), false)
})
