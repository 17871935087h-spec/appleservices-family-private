const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const code = fs.readFileSync(__dirname + '/primary-mail.js', 'utf8');
function setup(handler) {
  const elements = new Map();
  const node = id => {
    if (!elements.has(id)) elements.set(id, {value:'',checked:false,hidden:false,disabled:false,textContent:'',events:{},setAttribute(){},classList:{toggle(){}},addEventListener(name,fn){this.events[name]=fn;}});
    return elements.get(id);
  };
  let observe;
  const calls=[];
  const context = vm.createContext({document:{getElementById:node},selectedAccount:'fixture-01',token:'fixture-token',MutationObserver:class {constructor(fn){observe=fn;}observe(){}},window:{addEventListener(){}},fetch:async(url,options)=>{calls.push({url,body:JSON.parse(options.body)});return handler(url,options);}});
  vm.runInContext(code,context);
  return {node,calls,context,sync:()=>observe(),click:async()=>{node('primaryMailRead').events.click();await settle();},submit:async()=>{node('primaryMailForm').events.submit({preventDefault(){}});await settle();}};
}
const settle=()=>new Promise(resolve=>setImmediate(resolve));
const reply=value=>({ok:true,json:async()=>value});
test('state reads are explicit and existing primary address blocks create',async()=>{
 const ui=setup(()=>reply({account_id:'fixture-01',stage:'verified',email:'fixture@icloud.com',can_create:false,message:'已开通'}));
 assert.equal(ui.calls.length,0);assert.equal(ui.node('primaryMailCreate').disabled,true);
 await ui.click();assert.equal(ui.calls.length,1);assert.equal(ui.node('primaryMailAddress').textContent,'fixture@icloud.com');assert.equal(ui.node('primaryMailForm').hidden,true);
});
test('creation requires permanent confirmation and unknown response cannot retry',async()=>{
 const ui=setup(url=>{if(url.includes('/create'))throw new Error('timeout');return reply({account_id:'fixture-01',stage:'not_open',can_create:true});});
 await ui.click();assert.equal(ui.node('primaryMailCreate').disabled,true);
 ui.node('primaryMailPermanent').checked=true;ui.node('primaryMailPermanent').events.input();assert.equal(ui.node('primaryMailCreate').disabled,false);
 await ui.submit();assert.equal(ui.calls.length,2);assert.equal(ui.calls[1].body.allow_web_login,false);assert.equal(ui.node('primaryMailCreate').disabled,true);
 await ui.submit();assert.equal(ui.calls.length,2);assert.match(ui.node('primaryMailStatus').textContent,/待核验/);
});
test('account change discards the previous in-flight response',async()=>{
 let resolve;const wait=new Promise(done=>resolve=done);
 const ui=setup(()=>wait);ui.node('primaryMailRead').events.click();
 ui.context.selectedAccount='fixture-02';ui.sync();resolve(reply({account_id:'fixture-01',stage:'verified',email:'old@icloud.com'}));await settle();
 assert.equal(ui.node('primaryMailAddress').textContent,'');assert.equal(ui.node('primaryMailCreate').disabled,true);
});
