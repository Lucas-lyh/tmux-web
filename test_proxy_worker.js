'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs'), vm = require('node:vm');
const objects = new Map();
let sequence = 0;
class BlobFixture {
  constructor(parts, options={}) { this.source=parts.map(p=>p instanceof BlobFixture?p.source:String(p)).join(''); this.type=options.type; }
}
const create = blob => { const id='blob:http://fixture:59999/'+(++sequence); objects.set(id,blob); return id; };
const revoke = id => objects.delete(String(id));
class PageURL extends URL {}
PageURL.createObjectURL=create; PageURL.revokeObjectURL=revoke;
class WorkerURL extends URL {}
WorkerURL.revokeObjectURL=revoke;
class Element { setAttribute() {} }
class Xhr { open(method,url) { this.method=method;this.url=url; } }
class WorkerFixture {
  constructor(url,options={}) {
    if(options.fail) throw new Error('fixture constructor failure');
    this.source=objects.get(String(url))?.source;
    this.options=options; this.messages=[]; this.fetches=[];
  }
  addEventListener() {}
  terminate() { this.stopped=true; }
  run() {
    const worker=this;
    class WorkerXhr { open(method,url) { this.method=method;this.url=url; } }
    const scope={URL:WorkerURL, Request, XMLHttpRequest:WorkerXhr,
      postMessage:value=>worker.messages.push(value), fetch(...args){worker.fetches.push(args);return Promise.resolve({ok:true});}};
    scope.self=scope;
    scope.importScripts=(...urls)=>{for(const url of urls){assert.ok(objects.has(url),'source survives immediate caller revocation');vm.runInContext(objects.get(url).source,context);}};
    const context=vm.createContext(scope);this.scope=scope;
    vm.runInContext(this.source,context);
  }
  postMessage(value) { this.scope.onmessage({data:value}); }
}
const page={URL:PageURL, Blob:BlobFixture, Worker:WorkerFixture, Element, Request,
  XMLHttpRequest:Xhr, fetch(){}, location:new URL('http://fixture:59999/port/3080/'),
  history:{pushState(){},replaceState(){}},navigator:{}};
page.window=page;vm.runInNewContext(fs.readFileSync(0,'utf8'),page);
const source='"use strict";self.onmessage=e=>{const x=new XMLHttpRequest();x.open("POST",e.data.url);self.postMessage({url:x.url,strict:(function(){return this===undefined})(),unchanged:e.data.url});};';
const url=page.URL.createObjectURL(new BlobFixture([source],{type:'text/javascript'}));
const worker=new page.Worker(url,{name:'dsh-file-upload'});
page.URL.revokeObjectURL(url);
worker.run();
worker.postMessage({url:'http://fixture:59999/api/session/uploadFileBinary?name=fixture.md'});
assert.equal(worker.messages[0].url,'http://fixture:59999/port/3080/api/session/uploadFileBinary?name=fixture.md');
assert.equal(worker.messages[0].unchanged,'http://fixture:59999/api/session/uploadFileBinary?name=fixture.md');
assert.equal(worker.messages[0].strict,true,'original source keeps its strict directive');
assert.equal(objects.size,0,'bootstrap and snapshot URLs are released');
worker.scope.fetch('/api/upload',{method:'POST',body:'bytes'});
assert.equal(worker.fetches[0][0],'http://fixture:59999/port/3080/api/upload');
assert.equal(worker.fetches[0][1].body,'bytes');
worker.scope.fetch(new Request('http://fixture:59999/api/upload',{method:'POST',body:'original'}));
assert.equal(worker.fetches[1][0].url,'http://fixture:59999/port/3080/api/upload');
assert.equal(worker.fetches[1][0].method,'POST');
worker.scope.fetch('https://external.invalid/upload');
assert.equal(worker.fetches[2][0],'https://external.invalid/upload');
worker.postMessage({url:'http://fixture:59999/port/3080/api/upload'});
assert.equal(worker.messages[1].url,'http://fixture:59999/port/3080/api/upload');
worker.terminate();
const earlyUrl=page.URL.createObjectURL(new BlobFixture([source]));
const early=new page.Worker(earlyUrl);page.URL.revokeObjectURL(earlyUrl);early.terminate();
assert.equal(objects.size,0,'termination before startup releases the snapshot');
const failedUrl=page.URL.createObjectURL(new BlobFixture([source]));
assert.throws(()=>new page.Worker(failedUrl,{fail:true}),/fixture constructor failure/);
page.URL.revokeObjectURL(failedUrl);assert.equal(objects.size,0);
const moduleUrl=page.URL.createObjectURL(new BlobFixture(['export {};']));
const moduleWorker=new page.Worker(moduleUrl,{type:'module'});
assert.equal(moduleWorker.source,'export {};','module workers retain native loading semantics');
page.URL.revokeObjectURL(moduleUrl);
console.log('Blob worker routing, directives, revocation and body preservation passed');
