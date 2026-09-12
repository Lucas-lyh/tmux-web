'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/static/index.html', 'utf8').split('<script>')[1].split('</script>')[0];
const elements = new Map();
const encode = text => String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
function element(id) {
  if (elements.has(id)) return elements.get(id);
  const listeners = {}, children = new Map();
  const el = {id, listeners, dataset: {}, value: '', textContent: '', disabled: false, clientWidth: 800, clientHeight: 480,
    classList: {add(){}, remove(){}, toggle(){}}, style: {}, focus(){}, select(){}, appendChild(){}, remove(){}, click(){ this.clicked = true; },
    getBoundingClientRect: () => ({left:100, top:50, width:800, height:480}),
    addEventListener(name, fn){ listeners[name] = fn; },
    querySelector(selector){ if (!children.has(selector)) children.set(selector, element(id + selector)); return children.get(selector); },
    querySelectorAll(selector){
      if(selector!=='.noderevoke') return [];
      this.revokes=[...this.innerHTML.matchAll(/class="ghost noderevoke" data-id="([^"]+)" data-node="([^"]+)"/g)]
        .map(match=>({dataset:{id:match[1],node:match[2]}}));
      return this.revokes;
    }};
  Object.defineProperty(el, 'innerHTML', {get(){ return this.html === undefined ? encode(this.textContent) : this.html; }, set(value){ this.html = value; }});
  elements.set(id, el);
  return el;
}
const transfers = [], terminalMessages = [], anchors = [];
class FakeSocket {
  constructor(url) { this.url = url; this.readyState = 1; this.bufferedAmount = 0; this.sent = []; transfers.push(this); }
  send(message) { this.sent.push(message); }
  close() { this.readyState = 3; if (this.onclose) this.onclose(); }
}
class FakeTerminal {
  constructor(){ this.cols=80; this.rows=24; this.modes={mouseTrackingMode:'none'}; this.element=element('terminal-element'); this.element.dispatchEvent=ev=>this.dispatched=ev; }
  loadAddon(){} open(){} registerLinkProvider(provider){this.provider=provider;} onSelectionChange(){} onData(fn){this.dataHandler=fn;} onResize(){} attachCustomKeyEventHandler(){} focus(){} reset(){this.modes.mouseTrackingMode='none';} write(data){terminalMessages.push(data);} scrollLines(lines){this.scrolled=lines;} getSelection(){return '';}
}
let clock = 1000;
const sandbox = {console, TextEncoder, Uint8Array, ArrayBuffer, Blob, URL, Promise,
  Date: class extends Date {static now(){return clock;}},
  document: {getElementById: element, createElement(tag){const el=element('created-' + elements.size); if(tag==='a') anchors.push(el);return el;},
    querySelectorAll:()=>[], body:element('body'), addEventListener(){}, execCommand(){}},
  window: {addEventListener(){}, open(){}}, navigator: {},
  location: {protocol:'http:',host:'fixture:60001',hostname:'fixture',reload(){}},
  matchMedia:()=>({matches:false,addEventListener(){}}),
  fetch:()=>new Promise(()=>{}), WebSocket:FakeSocket, Terminal:FakeTerminal, FitAddon:{FitAddon:class{fit(){}}},
  ResizeObserver:class{observe(){}}, WheelEvent:class{constructor(type, values){this.type=type;Object.assign(this,values);}},
  setTimeout:()=>0,clearTimeout(){},setInterval:()=>0,clearInterval(){},requestAnimationFrame:()=>0,
  alert(){},confirm:()=>true,prompt:()=>null};
vm.createContext(sandbox);
vm.runInContext(source, sandbox);
const run = code => vm.runInContext(code, sandbox);
function select(node, session='work') {run(`sessionGeneration++; currentNode=${JSON.stringify(node)}; current=${JSON.stringify(node+':'+session)}; ws={readyState:1,sent:[],close(){this.readyState=3;},send(data){this.sent.push(data);}};`);}
const tick=()=>new Promise(resolve=>setImmediate(resolve));
(async () => {
  select('alpha');
  let finishCheck;
  sandbox.fetch=url=>{assert.match(url,/node=alpha/);return new Promise(resolve=>finishCheck=resolve);};
  const download=run('downloadPath("/tmp/file")');
  select('beta'); finishCheck({ok:true,status:200}); await download;
  assert.equal(anchors.length,0,'stale download must not create a link for the new node');

  select('alpha');
  let requests=[];
  sandbox.fetch=async url=>{requests.push(url);return {ok:true,json:async()=>({path:'/tmp/file'})};};
  await run('resolvePath("/tmp/file")');
  await run('resolvePath("/tmp/file")');
  assert.equal(requests.length,1,'positive cache reused within one node');
  select('beta');
  await run('resolvePath("/tmp/file")');
  assert.equal(requests.length,2,'same path on a different node needs a request');
  sandbox.fetch=async url=>{requests.push(url);return {ok:false};};
  await run('resolvePath("/tmp/missing")');
  await run('resolvePath("/tmp/missing")');
  assert.equal(requests.length,3);
  clock+=3001;
  await run('resolvePath("/tmp/missing")');
  assert.equal(requests.length,4,'negative cache expires');

  select('alpha');
  const upload=run('uploadFile({name:"fixture",size:0})');
  const transfer=transfers.at(-1);
  assert.match(transfer.url,/node=alpha/);
  await transfer.onopen();
  select('beta');
  transfer.onmessage({data:JSON.stringify({ok:true,path:'/tmp/uploaded'})});
  assert.equal(await upload,true);
  assert.equal(run('ws.sent.length'),0,'old upload must not type into the new terminal');
  const context=run('sessionContext()');
  run('sessionGeneration++');
  sandbox.oldContext=context;
  assert.equal(run('sendToContext(oldContext,"unsafe")'),false,'same session reconnect invalidates a context');

  run('ensureTerm()');
  select('remote');
  const wheel=element('term').listeners.wheel;
  let prevented=0;
  wheel({deltaY:120,deltaMode:0,clientX:500,clientY:290,preventDefault(){prevented++;},stopPropagation(){}});
  assert.equal(prevented,0,'remote wheel belongs to xterm');
  assert.equal(run('ws.sent.length'),0);
  run('sendWheel(3,true)');
  assert.equal(run('term.scrolled'),-3,'plain shell buttons scroll local history');
  run('term.modes.mouseTrackingMode="drag"; sendWheel(2,false)');
  assert.equal(run('term.dispatched.type'),'wheel','TUI buttons use xterm active mouse encoding');
  select('');
  wheel({deltaY:120,deltaMode:0,clientX:500,clientY:290,preventDefault(){prevented++;},stopPropagation(){}});
  assert.equal(run('ws.sent.length'),3,'local tmux keeps SGR wheel reporting');
  assert.deepEqual(JSON.parse(run('JSON.stringify(terminalCell(500,290))')),{col:41,row:13});

  run('sessCache=[{name:"remote:work",node:"remote"}]; attach("remote:work")');
  const terminalSocket=transfers.at(-1);
  terminalSocket.onmessage({data:new Uint8Array([27,91,63,49,48,48,48,104]).buffer});
  assert.deepEqual(Array.from(terminalMessages.at(-1)),[27,91,63,49,48,48,48,104],'remote mouse mode is not stripped');

  const posts=[];
  sandbox.fetch=async (url,options)=>{posts.push([url,options]);return {ok:true,json:async()=>({nodes:[],credentials:[],token:'one-use-fixture',port:60001,node_script_sha256:'abc'}),text:async()=>''};};
  await run('refreshNodes()');
  let copied=''; sandbox.navigator.clipboard={writeText:async text=>{copied=text;}};
  await element('nodes').querySelector('.nodejoin').onclick();
  assert.equal(posts.at(-1)[0],'/api/node-enroll');
  assert.equal(posts.at(-1)[1].method,'POST');
  assert.match(copied,/one-use-fixture/); assert.match(copied,/TMUX_WEB_NODE_TOKEN/);
  assert.doesNotMatch(copied,/info\.secret/);
  sandbox.navigator.clipboard.writeText=async()=>{throw new Error('gesture expired');};
  let fallback=''; sandbox.prompt=(message,command)=>{fallback=command;};
  await element('nodes').querySelector('.nodejoin').onclick();
  assert.match(fallback,/one-use-fixture/,'async clipboard refusal still exposes the usable command');

  const info={nodes:[{name:'online',sessions:1,credential_id:'online-id'}],
    credentials:[{id:'online-id',name:'online'},{id:'offline-id',name:'offline'}]};
  sandbox.fetch=async (url,options)=>{posts.push([url,options]);return {ok:true,json:async()=>url==='/api/nodes'?info:[],text:async()=>''};};
  await run('refreshNodes()');
  assert.equal(element('nodes').revokes.length,2,'both online and offline credentials can be revoked');
  await element('nodes').revokes.find(button=>button.dataset.id==='offline-id').onclick();
  const revoke=posts.find(([url])=>url==='/api/node-revoke');
  assert.equal(revoke[1].method,'POST');
  assert.deepEqual(JSON.parse(revoke[1].body),{id:'offline-id'});
  element('pwold').value='fixture-old'; element('pwnew').value=element('pwnew2').value='fixture-new';
  run('current=null');
  await element('pwsave').onclick();
  const password=posts.find(([url])=>url==='/api/passwd');
  assert.deepEqual(JSON.parse(password[1].body),{old:'fixture-old',new:'fixture-new'});
  assert.equal(password[1].method,'POST');
  assert.equal(element('pwold').value,'');
  console.log('Browser regressions passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
