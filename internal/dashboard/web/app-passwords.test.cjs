const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const code = fs.readFileSync(__dirname + '/app-passwords.js','utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));
const reply = value => ({ok:true,json:async() => value});
const accountReply = (stage, extra={}) => ({account_id:'account-1',stage,can_create:false,result_available:false,items:[],...extra});
function deferred() {
  let resolve;
  const promise = new Promise(yes => {resolve=yes;});
  return {promise,resolve};
}

function setup(handler, clipboard={writeText:async() => {}}) {
  const elements = new Map();
  const makeNode = id => ({
    id,value:'',checked:false,hidden:false,disabled:false,textContent:'',dataset:{},events:{},children:[],attributes:{},
    setAttribute(name,value){this.attributes[name]=String(value);},
    addEventListener(name,fn){this.events[name]=fn;},
    append(...children){this.children.push(...children);},
    replaceChildren(...children){this.children=[...children];},
    get innerHTML(){return '';},
    set innerHTML(_value){throw new Error('innerHTML is forbidden in the app-password module');}
  });
  const node = id => {if(!elements.has(id))elements.set(id,makeNode(id));return elements.get(id);};
  let observe;
  let uuid = 0;
  const calls = [];
  const document = {
    visibilityState:'visible',
    getElementById:node,
    createElement:tag => makeNode(tag),
    addEventListener(name,fn){node('document').events[name]=fn;}
  };
  const localWrites=[],sessionWrites=[];
  const context = vm.createContext({
    document,
    selectedAccount:'account-1',
    token:'fixture-token',
    MutationObserver:class {constructor(fn){observe=fn;}observe(){}},
    AbortController,
    crypto:{randomUUID:()=>'request-' + (++uuid)},
    navigator:{clipboard},
    localStorage:{setItem(...args){localWrites.push(args);}},
    sessionStorage:{setItem(...args){sessionWrites.push(args);}},
    window:{addEventListener(name,fn){node('window').events[name]=fn;}},
    fetch:async(url,options) => {
      calls.push({url,options,body:JSON.parse(options.body)});
      return handler(url,options,calls.length);
    }
  });
  vm.runInContext(code,context);
  return {
    node,calls,context,localWrites,sessionWrites,
    sync:() => observe(),
    async click(id){const fn=node(id).events.click;if(fn)await fn();await settle();},
    async submit(){const fn=node('appPasswordsCreateForm').events.submit;if(fn)await fn({preventDefault(){}});await settle();},
    async input(id){const fn=node(id).events.input;if(fn)await fn();await settle();},
    async changeVisibility(value){document.visibilityState=value;const fn=node('document').events.visibilitychange;if(fn)await fn();await settle();}
  };
}

test('no automatic request; explicit list read renders labels as text',async()=>{
  const injected='<img src=x onerror="globalThis.compromised=true">';
  const ui=setup(()=>reply(accountReply('ready',{can_create:true,items:[{id:'one',description:injected,created_at:'2026-11-09'}]})));
  assert.equal(ui.calls.length,0);
  assert.equal(ui.node('appPasswordsCreateForm').hidden,true);
  await ui.click('appPasswordsRead');
  assert.equal(ui.calls.length,1);
  assert.match(ui.calls[0].url,/\/api\/app-passwords\/status\?account=account-1$/);
  assert.equal(ui.calls[0].options.method,'POST');
  assert.equal(ui.calls[0].options.headers['X-App-Token'],'fixture-token');
  assert.equal(ui.node('appPasswordsItems').children[0].children[0].textContent,injected);
  assert.equal(ui.context.compromised,undefined);
  assert.equal(ui.localWrites.length,0);
  assert.equal(ui.sessionWrites.length,0);
});

test('empty list is called empty only after a successful explicit read',async()=>{
  const ui=setup(()=>reply(accountReply('ready',{can_create:true,items:[]})));
  assert.match(ui.node('appPasswordsEmpty').textContent,/尚未读取/);
  await ui.click('appPasswordsRead');
  assert.equal(ui.node('appPasswordsEmpty').textContent,'尚无专用密码。');
});

test('connect requires both explicit consents and sends only allowed flags',async()=>{
  const ui=setup(()=>reply(accountReply('ready',{can_create:true})));
  assert.equal(ui.node('appPasswordsConnect').disabled,true);
  await ui.click('appPasswordsConnect');
  assert.equal(ui.calls.length,0);
  ui.node('appPasswordsSaveConsent').checked=true;
  await ui.input('appPasswordsSaveConsent');
  ui.node('appPasswordsDeviceConsent').checked=true;
  await ui.input('appPasswordsDeviceConsent');
  assert.equal(ui.node('appPasswordsConnect').disabled,false);
  await ui.click('appPasswordsConnect');
  assert.equal(ui.calls.length,1);
  assert.match(ui.calls[0].url,/\/connect\?account=/);
  assert.deepEqual(ui.calls[0].body,{allow_web_login:true,allow_device_verification:true});
  assert.equal(ui.node('appPasswordsSaveConsent').checked,false);
  assert.equal(ui.node('appPasswordsDeviceConsent').checked,false);
});

test('create submits once with default label and double click cannot duplicate it',async()=>{
  let resolveCreate;
  const pending = new Promise(resolve => {resolveCreate=resolve;});
  const ui=setup(url=>{
    if(url.includes('/status'))return reply(accountReply('ready',{can_create:true}));
    return pending;
  });
  await ui.click('appPasswordsRead');
  const first=ui.submit();
  await settle();
  const second=ui.submit();
  await settle();
  assert.equal(ui.calls.length,2);
  assert.equal(ui.calls[1].body.description,'邮件客户端');
  assert.equal(ui.calls[1].body.allow_password_challenge,false);
  assert.equal(ui.calls[1].body.request_id,'request-1');
  resolveCreate(reply(accountReply('generated',{request_id:'request-1',result_available:true,password:'abcd-efgh'})));
  await Promise.all([first,second]);
  assert.equal(ui.node('appPasswordsSecret').textContent,'abcd-efgh');
  assert.equal(ui.node('appPasswordsSecretPanel').hidden,false);
});

test('label input and request payload truncate by Unicode code point',async()=>{
  const ui=setup(url=>reply(url.includes('/status')
    ? accountReply('ready',{can_create:true})
    : accountReply('generated',{request_id:'request-1',result_available:true,password:'secret-value'})));
  await ui.click('appPasswordsRead');
  ui.node('appPasswordsDescription').value='a'.repeat(63)+'😀x';
  await ui.input('appPasswordsDescription');
  const normalized=ui.node('appPasswordsDescription').value;
  assert.equal(Array.from(normalized).length,64);
  assert.equal(normalized,'a'.repeat(63)+'😀');
  await ui.submit();
  assert.equal(ui.calls[1].body.description,normalized);
});

test('recent result is fetched only by explicit request and uses its request id',async()=>{
  const ui=setup(url=>reply(url.includes('/status')
    ? accountReply('ready',{request_id:'recent-42',result_available:true,items:[{description:'邮件客户端'}]})
    : accountReply('generated',{request_id:'recent-42',result_available:true,password:'restored-result'})));
  await ui.click('appPasswordsRead');
  assert.equal(ui.node('appPasswordsShowResult').hidden,false);
  assert.equal(ui.node('appPasswordsSecret').textContent,'');
  await ui.click('appPasswordsShowResult');
  assert.match(ui.calls[1].url,/\/result\?account=/);
  assert.deepEqual(ui.calls[1].body,{request_id:'recent-42'});
  assert.equal(ui.node('appPasswordsSecret').textContent,'restored-result');
  assert.equal(ui.node('appPasswordsItems').children[0].children[0].textContent,'邮件客户端');
});

test('password_required continues only with checkbox and reuses request id and label',async()=>{
  let creates=0;
  const ui=setup(url=>{
    if(url.includes('/status'))return reply(accountReply('ready',{can_create:true}));
    creates++;
    if(creates===1)return reply(accountReply('password_required',{request_id:'request-1',description:'邮件客户端'}));
    return reply(accountReply('generated',{request_id:'request-1',result_available:true,password:'one-time'}));
  });
  await ui.click('appPasswordsRead');
  await ui.submit();
  assert.equal(ui.node('appPasswordsCreateForm').hidden,false);
  assert.equal(ui.node('appPasswordsCreate').disabled,true);
  ui.node('appPasswordsPasswordChallenge').checked=true;
  await ui.input('appPasswordsPasswordChallenge');
  assert.equal(ui.node('appPasswordsCreate').disabled,false);
  await ui.submit();
  assert.equal(creates,2);
  assert.equal(ui.calls[2].body.request_id,'request-1');
  assert.equal(ui.calls[2].body.description,'邮件客户端');
  assert.equal(ui.calls[2].body.allow_password_challenge,true);
  assert.equal(ui.node('appPasswordsSecret').textContent,'one-time');
});

test('unknown create result never retries automatically; list read and confirmation gate review',async()=>{
  let statusReads=0;
  const ui=setup(url=>{
    if(url.includes('/create'))throw new Error('raw backend detail must not be shown');
    if(url.includes('/review'))return reply(accountReply('ready',{can_create:true,items:[{description:'客户端'}]}));
    statusReads++;
    return reply(statusReads===1
      ? accountReply('ready',{can_create:true})
      : statusReads===2
        ? accountReply('outcome_unknown',{request_id:'request-1',items:[{description:'客户端'}]})
        : accountReply('ready',{can_create:true,items:[{description:'客户端'}]}));
  });
  await ui.click('appPasswordsRead');
  await ui.submit();
  assert.equal(ui.calls.filter(call=>call.url.includes('/create')).length,1);
  assert.match(ui.node('appPasswordsStatus').textContent,/待核对/);
  assert.equal(ui.node('appPasswordsCreateForm').hidden,true);
  await ui.click('appPasswordsCreate');
  assert.equal(ui.calls.filter(call=>call.url.includes('/create')).length,1);
  ui.node('appPasswordsReviewConfirm').checked=true;
  await ui.input('appPasswordsReviewConfirm');
  await ui.click('appPasswordsReviewButton');
  assert.equal(ui.calls.filter(call=>call.url.includes('/review')).length,0);
  await ui.click('appPasswordsRead');
  ui.node('appPasswordsReviewConfirm').checked=true;
  await ui.input('appPasswordsReviewConfirm');
  assert.equal(ui.node('appPasswordsReviewButton').disabled,false);
  await ui.click('appPasswordsReviewButton');
  assert.equal(ui.calls.filter(call=>call.url.includes('/review')).length,1);
  assert.deepEqual(ui.calls.find(call=>call.url.includes('/review')).body,{request_id:'request-1'});
  assert.equal(ui.calls.filter(call=>call.url.includes('/create')).length,1);
  assert.equal(ui.node('appPasswordsCreateForm').hidden,false);
  assert.doesNotMatch(ui.node('appPasswordsStatus').textContent,/raw backend detail/);
});

test('compatible session_required review unlocks locally but still requires an explicit ready-list read',async()=>{
  let statusReads=0;
  const ui=setup(url=>{
    if(url.includes('/create'))throw new Error('ambiguous create response');
    if(url.includes('/review'))return reply(accountReply('session_required'));
    statusReads++;
    return reply(statusReads===1
      ? accountReply('ready',{can_create:true})
      : statusReads===2
        ? accountReply('outcome_unknown',{request_id:'request-1'})
        : accountReply('ready',{can_create:true}));
  });
  await ui.click('appPasswordsRead');
  await ui.submit();
  await ui.click('appPasswordsRead');
  ui.node('appPasswordsReviewConfirm').checked=true;
  await ui.input('appPasswordsReviewConfirm');
  await ui.click('appPasswordsReviewButton');
  assert.equal(ui.node('appPasswordsCreateForm').hidden,true);
  assert.match(ui.node('appPasswordsStatus').textContent,/显式读取列表/);
  assert.equal(ui.calls.filter(call=>call.url.includes('/create')).length,1);
  await ui.click('appPasswordsRead');
  assert.equal(ui.node('appPasswordsCreateForm').hidden,false);
  assert.equal(ui.calls.filter(call=>call.url.includes('/create')).length,1);
});

test('account switch discards late response and clears displayed password',async()=>{
  let resolveStatus;
  const wait=new Promise(resolve=>{resolveStatus=resolve;});
  const ui=setup(url=>{
    if(url.includes('/status'))return wait;
    return reply(accountReply('generated',{request_id:'request-1',result_available:true,password:'secret-value'}));
  });
  const read=ui.click('appPasswordsRead');
  await settle();
  ui.context.selectedAccount='account-2';
  ui.sync();
  resolveStatus(reply({account_id:'account-1',stage:'ready',can_create:true,items:[{description:'stale'}]}));
  await read;
  assert.equal(ui.node('appPasswordsItems').children.length,0);
  assert.doesNotMatch(ui.node('appPasswordsStatus').textContent,/stale/);
  assert.equal(ui.node('appPasswordsSecret').textContent,'');
  assert.equal(ui.node('appPasswordsDescription').value,'邮件客户端');
});

test('account switch clears a currently displayed password',async()=>{
  const ui=setup(url=>reply(url.includes('/status')
    ? accountReply('ready',{can_create:true})
    : accountReply('generated',{request_id:'request-1',result_available:true,password:'secret-value'})));
  await ui.click('appPasswordsRead');
  await ui.submit();
  assert.equal(ui.node('appPasswordsSecret').textContent,'secret-value');
  ui.context.selectedAccount='account-2';
  ui.sync();
  assert.equal(ui.node('appPasswordsSecret').textContent,'');
  assert.equal(ui.node('appPasswordsSecretPanel').hidden,true);
});

test('page hide clears secret; clipboard failure shows safe recovery text',async()=>{
  const ui=setup(url=>reply(url.includes('/status')
    ? accountReply('ready',{can_create:true})
    : accountReply('generated',{request_id:'request-1',result_available:true,password:'secret-value'})),{writeText:async()=>{throw new Error('clipboard detail');}});
  await ui.click('appPasswordsRead');
  await ui.submit();
  await ui.click('appPasswordsCopy');
  assert.match(ui.node('appPasswordsStatus').textContent,/复制失败/);
  assert.doesNotMatch(ui.node('appPasswordsStatus').textContent,/clipboard detail/);
  await ui.changeVisibility('hidden');
  assert.equal(ui.node('appPasswordsSecret').textContent,'');
  assert.equal(ui.node('appPasswordsSecretPanel').hidden,true);
});

test('create result arriving while page is hidden is saved but never echoed into the page',async()=>{
  const pending=deferred();
  const ui=setup(url=>url.includes('/status')
    ? reply(accountReply('ready',{can_create:true}))
    : pending.promise);
  await ui.click('appPasswordsRead');
  const creating=ui.submit();
  await settle();
  await ui.changeVisibility('hidden');
  pending.resolve(reply(accountReply('generated',{request_id:'request-1',result_available:true,password:'late-secret'})));
  await creating;
  assert.equal(ui.node('appPasswordsSecret').textContent,'');
  assert.equal(ui.node('appPasswordsSecretPanel').hidden,true);
  assert.match(ui.node('appPasswordsStatus').textContent,/返回后显式恢复/);
  assert.equal(ui.node('appPasswordsShowResult').hidden,false);
});

test('explicit restore result arriving while page is hidden is never echoed into the page',async()=>{
  const pending=deferred();
  const ui=setup(url=>url.includes('/status')
    ? reply(accountReply('ready',{request_id:'request-1',result_available:true}))
    : pending.promise);
  await ui.click('appPasswordsRead');
  const restoring=ui.click('appPasswordsShowResult');
  await settle();
  await ui.changeVisibility('hidden');
  pending.resolve(reply(accountReply('generated',{request_id:'request-1',result_available:true,password:'late-secret'})));
  await restoring;
  assert.equal(ui.node('appPasswordsSecret').textContent,'');
  assert.equal(ui.node('appPasswordsSecretPanel').hidden,true);
  assert.match(ui.node('appPasswordsStatus').textContent,/返回后显式恢复/);
});
