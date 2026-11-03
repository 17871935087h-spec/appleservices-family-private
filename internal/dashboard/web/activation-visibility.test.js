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

const renderActivationSource = extractFunction(appSource, 'renderActivation')

function createHarness(options = {}) {
  const elements = new Map()
  const effects = { fetch: 0, action: 0, accept: 0 }
  const selectedAccount = options.selectedAccount ?? 'account-a'
  const context = {
    selectedAccount,
    activationAccount: options.activationAccount ?? selectedAccount,
    activationInfo: options.activationInfo ?? null,
    busy: options.busy ?? false,
    current: null,
    $ (id) {
      if (!elements.has(id)) {
        const attributes = new Map()
        if (id === 'activationICloudTerms' || id === 'activationMediaTerms') {
          attributes.set('href', 'https://terms.example.invalid/stale')
        }
        const element = {
          id,
          hidden: false,
          disabled: false,
          textContent: `stale ${id}`,
          getAttribute (name) { return attributes.get(name) ?? null },
          setAttribute (name, value) { attributes.set(name, String(value)) },
          removeAttribute (name) { attributes.delete(name) },
        }
        Object.defineProperty(element, 'href', {
          get () { return attributes.get('href') ?? '' },
          set (value) { attributes.set('href', String(value)) },
        })
        elements.set(id, element)
      }
      return elements.get(id)
    },
    fetch () { effects.fetch += 1; throw new Error('renderActivation must not fetch') },
    action () { effects.action += 1; throw new Error('renderActivation must not start an action') },
    acceptActivation () { effects.accept += 1; throw new Error('renderActivation must not accept terms') },
  }
  vm.createContext(context)
  vm.runInContext(renderActivationSource, context, { filename: 'app.js' })
  return {
    context,
    effects,
    element: (id) => context.$(id),
    render: (view) => context.renderActivation(view),
  }
}

const requiredActivation = {
  required: true,
  region: 'US',
  icloud_version: 'fixture-icloud-terms',
  media_version: 'fixture-media-terms',
  icloud_terms_url: 'https://terms.example.invalid/icloud',
  media_terms_url: 'https://terms.example.invalid/media',
}

function assertNoStaleTerms(harness) {
  for (const id of ['activationICloudTerms', 'activationMediaTerms']) {
    assert.equal(harness.element(id).hidden, true, `${id} should be hidden when its terms are stale`)
    assert.equal(harness.element(id).getAttribute('href'), null, `${id} should not retain an old URL`)
  }
  assert.equal(harness.element('activationVersions').hidden, true)
  assert.equal(harness.element('activationVersions').textContent, '')
}

test('keeps the activation card visible while the selected account is not ready', () => {
  const harness = createHarness({ activationInfo: requiredActivation })
  harness.render({ activation_ready: false, icloud_activated: false })

  assert.equal(harness.element('activationCard').hidden, false)
  assert.equal(harness.element('activationCheckButton').disabled, true)
  assert.equal(harness.element('activationAcceptButton').hidden, true)
  assertNoStaleTerms(harness)
})

test('keeps the activation card visible when activation is already recorded', () => {
  const harness = createHarness({ activationInfo: requiredActivation })
  harness.render({ activation_ready: false, icloud_activated: true })

  assert.equal(harness.element('activationCard').hidden, false)
  assert.equal(harness.element('activationCheckButton').disabled, true)
  assert.equal(harness.element('activationAcceptButton').hidden, true)
  assertNoStaleTerms(harness)
})

test('shows a manual check when ready and no terms need acceptance', () => {
  const harness = createHarness()
  harness.render({ activation_ready: true, icloud_activated: false })

  assert.equal(harness.element('activationCard').hidden, false)
  assert.equal(harness.element('activationCheckButton').hidden, false)
  assert.equal(harness.element('activationCheckButton').disabled, false)
  assert.equal(harness.element('activationAcceptButton').hidden, true)
})

test('shows acceptance only for required terms and disables both controls while busy', () => {
  const harness = createHarness({ activationInfo: requiredActivation })
  harness.render({ activation_ready: true, icloud_activated: false })

  assert.equal(harness.element('activationCard').hidden, false)
  assert.equal(harness.element('activationCheckButton').hidden, true)
  assert.equal(harness.element('activationAcceptButton').hidden, false)
  assert.equal(harness.element('activationICloudTerms').hidden, false)
  assert.equal(harness.element('activationMediaTerms').hidden, false)

  harness.context.busy = true
  harness.render({ activation_ready: true, icloud_activated: false })
  assert.equal(harness.element('activationCheckButton').disabled, true)
  assert.equal(harness.element('activationAcceptButton').disabled, true)
})

test('clears old terms when the selected account changes, including while not ready', () => {
  const harness = createHarness({
    selectedAccount: 'account-b',
    activationAccount: 'account-a',
    activationInfo: requiredActivation,
  })
  harness.render({ activation_ready: false, icloud_activated: false })

  assert.equal(harness.context.activationInfo, null)
  assert.equal(harness.context.activationAccount, '')
  assert.equal(harness.element('activationCard').hidden, false)
  assert.equal(harness.element('activationCheckButton').disabled, true)
  assert.equal(harness.element('activationAcceptButton').hidden, true)
  assertNoStaleTerms(harness)
})

test('shows an explanation and keeps controls disabled when no account is selected', () => {
  const harness = createHarness({ selectedAccount: '', activationAccount: '' })
  harness.render(null)

  assert.equal(harness.element('activationCard').hidden, false)
  assert.ok(harness.element('activationSummary').textContent.trim().length > 0)
  assert.equal(harness.element('activationCheckButton').disabled, true)
  assert.equal(harness.element('activationAcceptButton').disabled, true)
  assert.equal(harness.element('activationAcceptButton').hidden, true)
})

test('rendering activation state does not fetch, start an action, or accept terms', () => {
  const harness = createHarness({ activationInfo: requiredActivation })
  harness.render({ activation_ready: true, icloud_activated: false })

  assert.deepEqual(harness.effects, { fetch: 0, action: 0, accept: 0 })
})
