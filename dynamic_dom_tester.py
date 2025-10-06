# dynamic_dom_tester.py â€” ULTRA-MAX (fixed routing & context)
from __future__ import annotations

import logging
import os
from typing import Dict, List
import json

from playwright.sync_api import sync_playwright, Page, Frame, CDPSession, Error as PWError
from config import USER_AGENT  # â† gunakan UA normal dari config

logger = logging.getLogger("xsscanner.dynamic")

# ===================================================================
# GABUNGAN TAINT-TRACKING + XSS INSTRUMENTATION (v2, low-overhead)
#  - Sumber taint diperluas (history, storage, BroadcastChannel, WebSocket)
#  - Sink diperluas (setAttribute* untuk event handler, addEventListener)
#  - Stack capture ringkas (Error().stack) untuk tiap temuan
#  - De-dup temuan di sisi browser (cap + fingerprint)
# ===================================================================
TAINT_XSS_SCRIPT = r"""
(() => {
  if (window.__xss_injected_v2) return;
  window.__xss_injected_v2 = true;
  const now = Date.now;
  const cap = 800;
  const maxDetailLen = 1500;
  const X = Object;
  const taints = new WeakSet();
  const seen = new Set();

  function S(v){ try{ const o=new String(v); taints.add(o); return o; }catch(e){ return v; } }
  function mark(v){
    if (typeof v === "string") return S(v);
    if (v && typeof v === "object" && (v.constructor===String)) return S(String(v));
    return v;
  }
  function isTainted(v){ return taints.has(v) || (typeof v==="object" && v && taints.has(v)); }
  function short(s){ try{ return String(s).slice(0, maxDetailLen) }catch(e){ return "" } }
  function stack(){ try{ return (new Error()).stack?.split("\n").slice(2,7).join("\n")||"" }catch(e){ return "" } }
  function fp(type, detail){ return type + "|" + String(detail).slice(0, 80) + "|" + location.href }

  window.__xss_findings = window.__xss_findings || [];
  function pushFinding(type, detail){
    if (!detail) return;
    const f = fp(type, detail);
    if (seen.has(f)) return;
    seen.add(f);
    if (window.__xss_findings.length >= cap) return;
    window.__xss_findings.push({
      type: "tainted_" + type,
      detail: short(detail),
      timestamp: now(),
      frame: location.href,
      stack: stack()
    });
  }

  const sProto = String.prototype;
  ["concat","slice","substring","replace","trim","toLowerCase","toUpperCase","repeat","padStart","padEnd","substr"]
  .forEach((k)=>{
    const orig = sProto[k];
    if (!orig) return;
    X.defineProperty(sProto, k, {
      value: function(...args){
        const out = orig.apply(this, args);
        if (taints.has(this) || args.some(a=>taints.has(a))) return S(out);
        return out;
      }
    });
  });

  const L = Location.prototype;
  const D = Document.prototype;
  const W = Window.prototype;

  try{
    const g1 = X.getOwnPropertyDescriptor(L, "search");
    X.defineProperty(L, "search", { get(){ return mark(g1.get.call(this)) }, configurable:true });
  }catch{}
  try{
    const g2 = X.getOwnPropertyDescriptor(L, "hash");
    X.defineProperty(L, "hash", { get(){ return mark(g2.get.call(this)) }, configurable:true });
  }catch{}
  try{
    const g3 = X.getOwnPropertyDescriptor(L, "href");
    X.defineProperty(L, "href", { get(){ return mark(g3.get.call(this)) }, configurable:true });
  }catch{}
  try{
    const g4 = X.getOwnPropertyDescriptor(D, "URL") || X.getOwnPropertyDescriptor(HTMLDocument.prototype, "URL");
    X.defineProperty(document, "URL", { get(){ return mark(g4.get.call(this)) }, configurable:true });
  }catch{}
  try{
    const g5 = X.getOwnPropertyDescriptor(D, "referrer") || X.getOwnPropertyDescriptor(HTMLDocument.prototype, "referrer");
    X.defineProperty(document, "referrer", { get(){ return mark(g5.get.call(this)) }, configurable:true });
  }catch{}

  try{
    const cd = X.getOwnPropertyDescriptor(D, "cookie") || X.getOwnPropertyDescriptor(HTMLDocument.prototype, "cookie");
    X.defineProperty(document, "cookie", {
      get(){ return mark(cd.get.call(document)) },
      set(v){ return cd.set.call(document, mark(v)) },
      configurable:true
    });
  }catch{}
  try{
    const nd = X.getOwnPropertyDescriptor(W, "name") || X.getOwnPropertyDescriptor(window, "name");
    X.defineProperty(window, "name", {
      get(){ return mark(nd.get.call(this)) },
      set(v){ return nd.set.call(this, mark(v)) },
      configurable:true
    });
  }catch{}
  // Hook location sinks (assign/replace); note: may navigate away
  try{
    const loc = window.location;
    const oAssign = loc.assign.bind(loc);
    const oReplace = loc.replace.bind(loc);
    loc.assign = function(u){ try{ if (isTainted(u)) pushFinding('location_assign', u) }catch{} return oAssign(u) };
    loc.replace = function(u){ try{ if (isTainted(u)) pushFinding('location_replace', u) }catch{} return oReplace(u) };
  }catch{}
  try{
    const uget = URLSearchParams.prototype.get;
    URLSearchParams.prototype.get = function(k){ return mark(uget.call(this, k)) };
  }catch{}
  try{
    const vd = X.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    X.defineProperty(HTMLInputElement.prototype, "value", {
      get(){ return mark(vd.get.call(this)) },
      set(v){ return vd.set.call(this, v) },
      configurable:true
    });
  }catch{}
  try{
    const oget = Element.prototype.getAttribute;
    Element.prototype.getAttribute = function(n){
      const val = oget.call(this, n);
      if (typeof val==="string" && /^(data|aria)-/i.test(n)) return mark(val);
      return val;
    };
  }catch{}
  try{
    window.addEventListener("message", (e)=>{ if (typeof e.data==="string") mark(e.data) });
  }catch{}
  try{
    const fr = FileReader.prototype.readAsText;
    FileReader.prototype.readAsText = function(blob, ...args){
      this.addEventListener("load", function(){ try{ this.result = mark(this.result) }catch{} });
      return fr.call(this, blob, ...args);
    };
  }catch{}
  ["localStorage","sessionStorage"].forEach((key)=>{
    try{
      const store = window[key];
      ["getItem"].forEach((fn)=>{
        const o = store[fn];
        store[fn] = function(k){ const v = o.call(this, k); return typeof v==="string" ? mark(v) : v; }
      });
    }catch{}
  });
  try{
    const push = history.pushState;
    history.pushState = function(state, title, url){
      if (typeof url==="string") url = mark(url);
      return push.call(this, state, title, url);
    };
    const rep = history.replaceState;
    history.replaceState = function(state, title, url){
      if (typeof url==="string") url = mark(url);
      return rep.call(this, state, title, url);
    };
  }catch{}
  try{
    const BC = window.BroadcastChannel;
    if (BC){
      const _c = BC.prototype.constructor;
      BC.prototype.constructor = function(name){
        const ch = new _c(name);
        const onmsg = ch.onmessage;
        ch.onmessage = function(ev){ if (ev && typeof ev.data==="string") mark(ev.data); if (onmsg) return onmsg.apply(this, arguments) };
        return ch;
      }
    }
  }catch{}
  try{
    const WS = window.WebSocket;
    // jaga prototype: delegasi via wrapper, bukan overwrite buta
    window.WebSocket = function(url, prot){
      const ws = new WS(url, prot);
      try{ window.__xss_ws_list = window.__xss_ws_list || []; window.__xss_ws_list.push(ws); }catch(e){}
      ws.addEventListener("message", (ev)=>{ try{ if (typeof ev.data==="string") mark(ev.data) }catch{} });
      return ws;
    };
    window.WebSocket.prototype = WS.prototype;
  }catch{}

  function wrapSetter(obj, prop, label){
    try{
      const desc = X.getOwnPropertyDescriptor(obj, prop);
      if (!desc || !desc.set) return;
      X.defineProperty(obj, prop, {
        get: desc.get,
        set(v){
          try{ if (isTainted(v)) pushFinding(label, v) }catch{}
          return desc.set.call(this, v);
        },
        configurable: true
      });
    }catch{}
  }

  wrapSetter(Element.prototype, "innerHTML", "innerHTML");
  wrapSetter(Element.prototype, "outerHTML", "outerHTML");
  wrapSetter(Element.prototype, "textContent", "textContent");
  wrapSetter(Element.prototype, "innerText", "innerText");
  wrapSetter(HTMLInputElement.prototype, "value", "input_value");

  try{
    const iah = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(pos, html){
      try{ if (isTainted(html)) pushFinding("insertAdjacentHTML", pos+"|"+html) }catch{}
      return iah.call(this, pos, html);
    };
    const iat = Element.prototype.insertAdjacentText;
    Element.prototype.insertAdjacentText = function(pos, text){
      try{ if (isTainted(text)) pushFinding("insertAdjacentText", pos+"|"+text) }catch{}
      return iat.call(this, pos, text);
    };
    const iae = Element.prototype.insertAdjacentElement;
    if (iae){
      Element.prototype.insertAdjacentElement = function(pos, el){
        try{
          const outer = el && typeof el.outerHTML === "string" ? el.outerHTML : "";
          if (outer && isTainted(outer)) pushFinding("insertAdjacentElement", pos+"|"+outer);
        }catch{}
        return iae.call(this, pos, el);
      };
    }
  }catch{}

  ["write","writeln"].forEach((fn)=>{
    try{
      const o = document[fn];
      document[fn] = function(s){
        try{ if (isTainted(s)) pushFinding("document."+fn, s) }catch{}
        return o.call(document, s);
      };
    }catch{}
  });

  // Classic sinks via Document prototype (covers some overrides)
  try{
    const _dw = Document.prototype.write;
    Document.prototype.write = function(html){
      try{ if (typeof html==="string" && isTainted(html)) pushFinding("document_write", html); }catch(e){}
      return _dw.apply(this, arguments);
    };
    const _dwn = Document.prototype.writeln;
    Document.prototype.writeln = function(html){
      try{ if (typeof html==="string" && isTainted(html)) pushFinding("document_writeln", html); }catch(e){}
      return _dwn.apply(this, arguments);
    };
  }catch{}

  try{
    const _eval = window.eval;
    window.eval = function(code){ try{ if (isTainted(code)) pushFinding("eval", code) }catch{} return _eval.call(window, code) };
  }catch{}
  try{
    const F = window.Function;
    window.Function = function(...args){ try{ if (args.some(isTainted)) pushFinding("Function", args.join(",")) }catch{} return F.apply(this, args) };
  }catch{}

  ["setTimeout","setInterval"].forEach((fn)=>{
    try{
      const o = window[fn];
      window[fn] = function(cb, t){
        try{ if (typeof cb==="string" && isTainted(cb)) pushFinding(fn, cb) }catch{}
        return o.call(this, cb, t);
      };
    }catch{}
  });

  // Hook alert/prompt/confirm/print to mark execution explicitly
  try{
    const markExec = ()=>{ try{ window.__xss_executed = true }catch{} };
    ['alert','confirm','prompt','print'].forEach(fn=>{
      try{
        const o = window[fn];
        Object.defineProperty(window, fn, { value: function(...a){ markExec(); try{ pushFinding('dialog_'+fn, a && a[0] || fn) }catch(e){} try{return o.apply(this,a)}catch(e){} } });
      }catch(e){}
    });
  }catch{}

  // Capture CSP violations
  try{
    document.addEventListener('securitypolicyviolation', function(e){
      try{ pushFinding('csp_violation', (e.violatedDirective||'')+" "+(e.blockedURI||'')) }catch{}
    });
  }catch{}

  ["onclick","onerror","onload","onmouseover","onfocus","onblur"].forEach((ev)=>{
    wrapSetter(HTMLElement.prototype, ev, "event_"+ev);
  });
  try{
    const ael = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, listener, opts){
      try{
        if (typeof listener === "string" && isTainted(listener)) pushFinding("addEventListener_"+type, listener);
      }catch{}
      return ael.call(this, type, listener, opts);
    };
  }catch{}

  try{
    const cssSet = CSSStyleDeclaration.prototype.setProperty;
    CSSStyleDeclaration.prototype.setProperty = function(n, v, p){
      try{ if (isTainted(v)) pushFinding("css_setProperty", n+"="+v) }catch{}
      return cssSet.call(this, n, v, p);
    };
    const cssTxt = Object.getOwnPropertyDescriptor(CSSStyleDeclaration.prototype, "cssText");
    if (cssTxt && cssTxt.set){
      Object.defineProperty(CSSStyleDeclaration.prototype, "cssText", {
        get: cssTxt.get,
        set(v){ try{ if (isTainted(v)) pushFinding("cssText", v) }catch{} return cssTxt.set.call(this, v) },
        configurable: true
      });
    }
    // Track stylesheet rule injection
    const ins = CSSStyleSheet && CSSStyleSheet.prototype && CSSStyleSheet.prototype.insertRule;
    if (ins){
      CSSStyleSheet.prototype.insertRule = function(rule, index){
        try{ if (isTainted(rule)) pushFinding("css_insertRule", rule) }catch{}
        return ins.call(this, rule, index);
      };
    }
  }catch{}

  // Extra sinks: DOMParser, Range, setAttributeNS/Node, jQuery helpers, and element append/prepend
  try{
    const _parse = DOMParser.prototype.parseFromString;
    DOMParser.prototype.parseFromString = function(str, type){
      try{ if (isTainted(str)) pushFinding("DOMParser.parseFromString", str) }catch{}
      return _parse.call(this, str, type);
    };
  }catch{}
  try{
    const _rcf = Range.prototype.createContextualFragment;
    Range.prototype.createContextualFragment = function(str){
      try{ if (isTainted(str)) pushFinding("createContextualFragment", str) }catch{}
      return _rcf.call(this, str);
    };
  }catch{}
  // Range.insertNode (mXSS via fragments/nodes)
  try{
    const _rin = Range.prototype.insertNode;
    Range.prototype.insertNode = function(n){
      try{
        const s = (typeof n==="string") ? n : ((n && n.outerHTML) || "");
        if (s && isTainted(s)) pushFinding("range_insertNode", s);
      }catch(e){}
      return _rin.apply(this, arguments);
    };
  }catch{}
  try{
    const san = Element.prototype.setAttributeNS;
    Element.prototype.setAttributeNS = function(ns, name, value){
      try{
        const key = String(name||"").toLowerCase();
        if ((/^on[a-z]+$/.test(key) || ["href","src","srcset","action","style","data","value","formaction","poster","xlink:href","data-src","data-href","data-url"].includes(key)) && isTainted(value)){
          pushFinding("setAttributeNS_"+key, value);
        }
      }catch{}
      return san.call(this, ns, name, value);
    };
  }catch{}
  try{
    const saNode = Element.prototype.setAttributeNode;
    Element.prototype.setAttributeNode = function(attr){
      try{
        const key = String(attr && attr.name || "").toLowerCase();
        const val = attr && attr.value;
        if ((/^on[a-z]+$/.test(key) || ["href","src","srcset","action","style","data","value","formaction","poster","xlink:href","data-src","data-href","data-url"].includes(key)) && isTainted(val)){
          pushFinding("setAttributeNode_"+key, val);
        }
      }catch{}
      return saNode.call(this, attr);
    };
  }catch{}
  ["append","prepend","before","after","replaceChildren","replaceWith"].forEach((fn)=>{
    try{
      const o = Element.prototype[fn];
      if (!o) return;
      Element.prototype[fn] = function(...args){
        try{ args.forEach(a=>{ if (typeof a==="string" && isTainted(a)) pushFinding("element_"+fn, a) }); }catch{}
        return o.apply(this, args);
      };
    }catch{}
  });

  [typeof DocumentFragment !== 'undefined' ? DocumentFragment.prototype : null,
   typeof ShadowRoot !== 'undefined' ? ShadowRoot.prototype : null].forEach((proto)=>{
    try{
      if (!proto) return;
      ["append","prepend","before","after","replaceChildren","replaceWith"].forEach((fn)=>{
        const o = proto[fn];
        if (!o) return;
        proto[fn] = function(...args){
          try{ args.forEach(a=>{ if (typeof a==="string" && isTainted(a)) pushFinding("fragment_"+fn, a) }); }catch{}
          return o.apply(this, args);
        };
      });
    }catch{}
  });

  // === Shadow DOM instrumentation (open shadow roots) ===
  try{
    function instrumentRoot(root){
      try{
        try{ const mo = new MutationObserver(()=>{}); mo.observe(root, {subtree:true, childList:true, attributes:true, characterData:true}); }catch(e){}
        try{
          const evs = ["click","input","change","focus","blur","keydown","keyup","wheel","pointerdown","pointerup","animationend","transitionend"];
          const nodes = root.querySelectorAll("a,button,[onclick],input,textarea,select,[tabindex]");
          nodes.forEach((el)=>{ evs.forEach(t=>{ try{ el.dispatchEvent(new Event(t,{bubbles:true,cancelable:true})) }catch(e){} }); });
        }catch(e){}
      }catch(e){}
    }
    const _attach = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function(init){
      const root = _attach.call(this, init);
      try{ if (init && init.mode === 'open') instrumentRoot(root); }catch(e){}
      return root;
    };
    try{ document.querySelectorAll('*').forEach(el=>{ if (el.shadowRoot) instrumentRoot(el.shadowRoot); }); }catch(e){}
  }catch(e){}

  // === Pump same-origin frames lightly ===
  try{
    (function pumpFrames(){
      try{
        for (let i=0;i<window.frames.length;i++){
          const f = window.frames[i];
          try{
            try{ f.dispatchEvent(new Event('hashchange')); }catch(e){}
            const d = f.document;
            const evs = ["click","input","change","keydown","keyup"];
            d.querySelectorAll("a,button,input,textarea,select,[tabindex]").forEach(el=>{
              evs.forEach(t=>{ try{ el.dispatchEvent(new Event(t,{bubbles:true})) }catch(e){} });
            });
          }catch(e){}
        }
      }catch(e){}
    })();
  }catch(e){}
  try{
    const wrapJQ = ($)=>{
      try{
        const fns = ["html","append","prepend","before","after","replaceWith"];
        fns.forEach(fn=>{
          if ($ && $.fn && typeof $.fn[fn] === "function"){
            const orig = $.fn[fn];
            $.fn[fn] = function(arg){
              try{ if (typeof arg === "string" && isTainted(arg)) pushFinding("jquery_"+fn, arg) }catch{}
              return orig.apply(this, arguments);
            };
          }
        });
      }catch{}
    };
    if (window.jQuery) wrapJQ(window.jQuery);
    if (window.$ && window.$.fn) wrapJQ(window.$);
  }catch{}

  try{
    const sa = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value){
      try{
        const key = String(name || "").toLowerCase();
        if ((/^on[a-z]+$/.test(key) || ["href","src","srcset","action","style","data","value","formaction","poster","xlink:href","data-src","data-href","data-url"].includes(key)) && isTainted(value)){
          pushFinding("setAttribute_"+key, value);
        }
      }catch{}
      return sa.call(this, name, value);
    };
  }catch{}

  try{
    const XHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function(){
      const xhr = new XHR();
      const o = xhr.open;
      xhr.open = function(m, u){
        try{ if (isTainted(u)) pushFinding("xhr_open", m+" "+u) }catch{}
        return o.apply(xhr, arguments);
      };
      return xhr;
    };
  }catch{}
  try{
    const _fetch = window.fetch;
    window.fetch = function(input, init){
      try{
        const u = typeof input==="string" ? input : input && input.url;
        if (isTainted(u)) pushFinding("fetch", u);
      }catch{}
      return _fetch.call(this, input, init);
    };
  }catch{}
  try{
    const sb = navigator.sendBeacon;
    if (typeof sb === "function"){
      navigator.sendBeacon = function(url, data){
        try{ if (isTainted(url)) pushFinding("sendBeacon", url); }catch{}
        return sb.call(this, url, data);
      };
    }
  }catch{}
  try{
    const wopen = window.open;
    if (typeof wopen === "function"){
      window.open = function(url, target, features){
        try{ if (isTainted(url)) pushFinding("window_open", url); }catch{}
        return wopen.call(this, url, target, features);
      };
    }
  }catch{}

  // Hook console methods to capture hints
  try{
    ['log','info','warn','error'].forEach(fn=>{
      const o = console[fn];
      console[fn] = function(...a){ try{ const s=(a||[]).map(x=>String(x)).join(' '); pushFinding('console_'+fn, s) }catch(e){} try{ return o.apply(this,a) }catch(e){} };
    });
  }catch{}

  // 1) Node-level children ops: appendChild/insertBefore
  try{
    (function(){
      const N = Node.prototype;
      function wrap(obj, fn, label){
        try{
          const o = obj[fn];
          if (!o) return;
          obj[fn] = function(a,b){
            try{
              const s = (typeof a === 'string') ? a : ((a && a.outerHTML) || '');
              if (s && isTainted(s)) pushFinding(label, s);
            }catch(e){}
            return o.apply(this, arguments);
          };
        }catch(e){}
      }
      wrap(N, 'appendChild', 'appendChild');
      wrap(N, 'insertBefore', 'insertBefore');
      wrap(N, 'replaceChild', 'replaceChild');
    })();
  }catch{}

  // 2) Property setters for src/href/srcdoc (not only setAttribute)
  try{
    (function(){
      function wrapSet(Ctor, prop, label){
        try{
          const d = Object.getOwnPropertyDescriptor(Ctor.prototype, prop);
          if (!d || !d.set) return;
          Object.defineProperty(Ctor.prototype, prop, {
            get: d.get,
            set(v){ try{ if (isTainted(v)) pushFinding(label, v) }catch(e){} return d.set.call(this, v); },
            configurable: true
          });
        }catch(e){}
      }
      [window.HTMLScriptElement, window.HTMLImageElement, window.HTMLIFrameElement, window.HTMLMediaElement, window.HTMLLinkElement].forEach(C=>{
        try{ if (C) wrapSet(C, 'src', (C.name||'elem').toLowerCase()+'_src') }catch(e){}
      });
      try{ if (window.HTMLAnchorElement) wrapSet(window.HTMLAnchorElement, 'href', 'a_href') }catch(e){}
      try{ if (window.HTMLIFrameElement) wrapSet(window.HTMLIFrameElement, 'srcdoc', 'iframe_srcdoc') }catch(e){}
    })();
  }catch{}

  // 3) Trusted Types & Sanitizer API (Chromium newer APIs)
  try{
    (function(){
      try{
        const tt = window.trustedTypes;
        if (tt && tt.createPolicy){
          const orig = tt.createPolicy;
          tt.createPolicy = function(name, rules){ try{ pushFinding('trustedTypes_policy', String(name)) }catch(e){} return orig.call(this, name, rules); };
        }
      }catch(e){}
      try{
        const d = Object.getOwnPropertyDescriptor(Element.prototype, 'setHTML');
        if (d && d.value){
          Object.defineProperty(Element.prototype, 'setHTML', { value: function(a,b){ try{ if (isTainted(a)) pushFinding('Element.setHTML', a) }catch(e){} return d.value.call(this, a, b); } });
        }
      }catch(e){}
      try{
        const S = window.Sanitizer;
        if (S && S.prototype && S.prototype.sanitize){
          const o = S.prototype.sanitize;
          S.prototype.sanitize = function(x){ try{ if (isTainted(x)) pushFinding('Sanitizer.sanitize_in', x) }catch(e){} const r = o.call(this, x); return r; };
        }
      }catch(e){}
    })();
  }catch{}

  // 4) DOMPurify hook (if present)
  try{
    (function(){
      const D = window.DOMPurify;
      if (D && typeof D.sanitize === 'function'){
        const o = D.sanitize;
        D.sanitize = function(x, opts){
          try{ if (isTainted(x)) pushFinding('DOMPurify_in', String(x).slice(0,500)) }catch(_){ }
          const r = o.call(this, x, opts);
          try{ if (typeof r === 'string' && r.indexOf('__xss_marker__') !== -1) pushFinding('DOMPurify_passed_marker', r) }catch(_){ }
          return r;
        };
      }
    })();
  }catch{}

  try{
    const la = Location.prototype.assign;
    Location.prototype.assign = function(u){ try{ if (isTainted(u)) pushFinding("location_assign", u) }catch{} return la.call(this, u) };
    const lr = Location.prototype.replace;
    Location.prototype.replace = function(u){ try{ if (isTainted(u)) pushFinding("location_replace", u) }catch{} return lr.call(this, u) };
  }catch{}

  // Property setter sinks for common URL-bearing elements
  try{
    const wrapSetterProp = (proto, prop, label) => {
      try{
        const desc = Object.getOwnPropertyDescriptor(proto, prop);
        if (!desc || !desc.set) return;
        Object.defineProperty(proto, prop, {
          get: desc.get,
          set(v){ try{ if (isTainted(v)) pushFinding(label, v) }catch{} return desc.set.call(this, v) },
          configurable: true
        });
      }catch{}
    };
    wrapSetterProp(HTMLScriptElement.prototype, 'src', 'prop_script_src');
    wrapSetterProp(HTMLImageElement.prototype, 'src', 'prop_img_src');
    wrapSetterProp(HTMLAnchorElement.prototype, 'href', 'prop_a_href');
    wrapSetterProp(HTMLIFrameElement.prototype, 'src', 'prop_iframe_src');
    if (Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc')){
      wrapSetterProp(HTMLIFrameElement.prototype, 'srcdoc', 'prop_iframe_srcdoc');
    }
    try{ if (window.HTMLSourceElement) wrapSetterProp(HTMLSourceElement.prototype, 'src', 'prop_source_src'); }catch(e){}
    try{ if (window.HTMLSourceElement) wrapSetterProp(HTMLSourceElement.prototype, 'srcset', 'prop_source_srcset'); }catch(e){}
    try{ if (window.HTMLVideoElement) wrapSetterProp(HTMLVideoElement.prototype, 'poster', 'prop_video_poster'); }catch(e){}
    try{ if (window.HTMLFormElement) wrapSetterProp(HTMLFormElement.prototype, 'action', 'prop_form_action'); }catch(e){}
    try{ if (window.HTMLLinkElement) wrapSetterProp(HTMLLinkElement.prototype, 'href', 'prop_link_href'); }catch(e){}
    try{ if (window.HTMLInputElement) wrapSetterProp(HTMLInputElement.prototype, 'formAction', 'prop_input_formaction'); }catch(e){}
  }catch{}

  try{
    const tpl = HTMLTemplateElement?.prototype;
    if (tpl){
      const d = Object.getOwnPropertyDescriptor(tpl, "innerHTML");
      if (d && d.set){
        Object.defineProperty(tpl, "innerHTML", {
          get: d.get,
          set(v){ try{ if (isTainted(v)) pushFinding("template_innerHTML", v) }catch{} return d.set.call(this, v) },
          configurable: true
        });
      }
    }
  }catch{}

  try{
    new MutationObserver((muts)=>{
      muts.forEach((m)=>{
        try{
          if (m.type==="childList"){
            m.addedNodes.forEach((n)=>{
              const h = (n && n.outerHTML) ? n.outerHTML : (n && n.textContent);
              if (h && typeof h==="string" && h.length) {
                // catat node baru (heuristik ringan agar tidak kebanjiran)
                if (h.length > 0 && h.length <= 20000) pushFinding("DOM_add", h);
              }
            });
          } else if (m.type==="attributes"){
            const v = m.target?.getAttribute?.(m.attributeName);
            if (v && isTainted(v)) pushFinding("DOM_attr", m.attributeName+"="+v);
          }
        }catch{}
      });
    }).observe(document, {childList:true, subtree:true, attributes:true});
  }catch{}
})();
"""

def _collect_findings(target: Page | Frame, findings: List[Dict], timeout: int) -> None:
    # Watch window ~5s in small ticks to give event-based payloads a chance
    try:
        for _ in range(10):
            target.wait_for_timeout(500)
    except PWError:
        pass

    try:
        target.evaluate("""
            () => {
              const evs = [
                "click","dblclick","contextmenu","focus","blur","input","change","submit",
                "keydown","keyup","keypress","wheel",
                "pointerdown","pointerup","pointerover","pointerout",
                "touchstart","touchend",
                "animationend","transitionend",
                "visibilitychange","popstate","storage","dragstart","dragend","hashchange"
              ];
              document.querySelectorAll('*').forEach(el=>{
                evs.forEach(name=>{ try{ el.dispatchEvent(new Event(name, {bubbles:true})) }catch(e){} });
              });
              // pump microtasks & RAF a bit
              try{ requestAnimationFrame(()=>{}); }catch(e){}
              try{ setTimeout(()=>{},0); }catch(e){}
            }
        """)
        target.wait_for_timeout(400)
    except PWError:
        pass

    try:
        if isinstance(target, Page):
            target.keyboard.press("Tab")
            target.keyboard.type("xss")
            target.wait_for_timeout(120)
    except PWError:
        pass

    try:
        data = target.evaluate("() => (window.__xss_findings||[]).slice()")
    except PWError:
        try:
            if isinstance(target, Page):
                target.wait_for_load_state("load", timeout=timeout)
            data = target.evaluate("() => (window.__xss_findings||[]).slice()")
        except PWError:
            data = []

    for f in data or []:
        if not isinstance(f, dict):
            continue
        minimal = {
            "type": f.get("type"),
            "detail": f.get("detail"),
            "timestamp": f.get("timestamp"),
            "frame": f.get("frame"),
        }
        if "stack" in f: minimal["stack"] = f["stack"]
        if minimal not in findings:
            findings.append(minimal)


def _fuzz_hash(page, payloads):
    try:
        for p in (payloads or [])[:10]:
            try:
                page.evaluate(f"location.hash = {json.dumps(p)}")
            except Exception:
                continue
            try:
                page.wait_for_timeout(250)
                page.evaluate("window.dispatchEvent(new Event('hashchange'))")
                page.wait_for_timeout(250)
            except Exception:
                pass
    except Exception:
        pass


def dynamic_dom_inspect(url: str, timeout: int = 30000, hash_fuzz: bool = True, fuzz_payloads: List[str] | None = None) -> List[Dict]:
    # Ensure Windows loop policy supports subprocess for Playwright
    if os.name == 'nt':
        try:
            import asyncio
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except Exception:
            pass
    findings: List[Dict] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=[
                "--disable-http2",  # mitigate net::ERR_HTTP2_PROTOCOL_ERROR targets
            ],
        )

        # ===== Context dgn UA & Locale Indonesia + header wajar =====
        context = browser.new_context(
            java_script_enabled=True,
            user_agent=USER_AGENT,
            locale="id-ID",
            timezone_id="Asia/Jakarta",
            ignore_https_errors=True,
        )
        context.set_extra_http_headers({
            "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"
        })

        # ===== Routing berbasis resource_type (AMAN utk dokumen utama) =====
        def _route(route):
            try:
                req = route.request
                rtype = getattr(req, "resource_type", None) or req.resource_type
                url_l = req.url.lower()

                # Jangan pernah blokir dokumen / navigasi utama
                if rtype in ("document", "xhr", "fetch", "websocket"):
                    return route.continue_()

                # Blokir aset berat berdasar resource_type
                if rtype in ("image", "media", "font", "stylesheet"):
                    return route.abort()

                # Plus jaga-jaga via ekstensi file
                if any(url_l.endswith(ext) for ext in (
                    ".png",".jpg",".jpeg",".gif",".webp",".svg",".ico",
                    ".woff",".woff2",".ttf",".otf",".mp4",".mp3",".pdf",
                    ".zip",".rar"
                )):
                    return route.abort()
            except Exception:
                pass
            return route.continue_()

        context.route("**/*", _route)

        # ===== New page (stealth opsional) =====
        page = context.new_page()
        # Capture console and page errors as additional signals
        try:
            _signals: List[Dict] = []
            def _log_console(msg):
                try:
                    _signals.append({"type":"console","detail": msg.text()})
                except Exception:
                    pass
            def _log_error(err):
                try:
                    _signals.append({"type":"pageerror","detail": str(err)})
                except Exception:
                    pass
            page.on("console", _log_console)
            page.on("pageerror", _log_error)
        except PWError:
            pass
        try:
            nav = None
            try:
                page.add_init_script(TAINT_XSS_SCRIPT)
                nav = page.goto(url, wait_until="load", timeout=timeout)
            except PWError as exc:
                logger.debug(f"dynamic_dom_inspect initial load failed for {url}: {exc}")
                # fallback: cabut routing & retry lebih permisif
                try:
                    context.unroute("**/*")
                except Exception:
                    pass
                try:
                    page.add_init_script(TAINT_XSS_SCRIPT)
                    nav = page.goto(url, wait_until="domcontentloaded", timeout=timeout * 2)
                except PWError as exc_retry:
                    logger.warning(
                        "dynamic_dom_inspect unable to navigate %s: %s",
                        url,
                        exc_retry,
                    )
                    return []

            # Fuzz location.hash to trigger SPA sinks (optional)
            if hash_fuzz:
                try:
                    pays = list(fuzz_payloads or [])
                except Exception:
                    pays = []
                if not pays:
                    try:
                        from config import CONTEXT_MIN_PAYLOADS
                        base = []
                        base += (CONTEXT_MIN_PAYLOADS.get('js_string_dq', []) or [])
                        base += (CONTEXT_MIN_PAYLOADS.get('js_string_sq', []) or [])
                        base += (CONTEXT_MIN_PAYLOADS.get('html_tag', []) or [])
                    except Exception:
                        base = []
                    base = (['xss', 'xss=1'] + base)
                    pays = []
                    for b in base:
                        pays.append(f"x={b}")
                        pays.append(str(b))
                _fuzz_hash(page, pays)

            # Collect CSP header + meta and push as finding
            try:
                hdr = ""
                try:
                    if nav:
                        hmap = getattr(nav, 'headers', lambda: {})() or {}
                        hdr = hmap.get('content-security-policy', '') or hmap.get('Content-Security-Policy', '') or ''
                except Exception:
                    hdr = ""
                html_doc = page.content() or ""
                from utils import parse_csp, extract_meta_csp, derive_csp_flags
                meta = extract_meta_csp(html_doc)
                raw = hdr or meta or ''
                flags = derive_csp_flags(parse_csp(raw)) if raw else {}
                if raw or flags:
                    findings.append({"type": "csp_flags", "detail": json.dumps({"raw": raw, "flags": flags}), "frame": page.url})
            except Exception:
                pass

            # Mark presence of sandbox iframes for classification
            try:
                page.evaluate(
                    """
                    () => {
                      try{
                        (window.__xss_findings = window.__xss_findings||[]);
                        document.querySelectorAll('iframe[sandbox]').forEach((ifr)=>{
                          try{ window.__xss_findings.push({type:'sandbox_iframe', detail: (ifr.getAttribute('sandbox')||''), frame: location.href, timestamp: Date.now()}); }catch(e){}
                        });
                      }catch(e){}
                    }
                    """
                )
            except PWError:
                pass

            # Trigger postMessage & WS events to force DOMXSS channels
            try:
                page.evaluate("""
                  (() => {
                    try {
                      (window.__xss_ws_list||[]).forEach(ws=>{ try{ ws.send('__XSS__'+Math.random()) }catch(e){} });
                      try{ window.postMessage('__XSS__'+Math.random(), '*'); }catch(e){}
                      try{ window.dispatchEvent(new MessageEvent('message', {data:'__XSS__'})); }catch(e){}
                      try{ window.dispatchEvent(new HashChangeEvent('hashchange')); }catch(e){}
                    } catch (e) {}
                  })();
                """)
            except PWError:
                pass

            try:
                _collect_findings(page, findings, timeout)
            except Exception as e:
                logger.warning(f"collect on main page failed: {e}")

            for fr in page.frames:
                try:
                    if fr.url and hasattr(page, "url") and fr.url == page.url:
                        continue
                    _collect_findings(fr, findings, timeout)
                except Exception as e:
                    logger.debug(f"collect on frame {getattr(fr,'url', '')} failed: {e}")

        finally:
            try: page.close()
            except Exception: pass
            try: context.close()
            except Exception: pass
            try: browser.close()
            except Exception: pass

    # Merge signal logs (console/pageerror) if captured
    try:
        findings.extend(_signals)  # type: ignore[name-defined]
    except Exception:
        pass

    uniq, seen = [], set()
    for f in findings:
        key = (f.get("type"), (f.get("detail") or "")[:100], f.get("frame"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)

    return uniq


def run_with_coverage(url: str, inject_js: str, timeout: int = 30000) -> int:
    if os.name == 'nt':
        try:
            import asyncio
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except Exception:
            pass
    total = 0
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            java_script_enabled=True,
            user_agent=USER_AGENT,
            locale="id-ID",
            timezone_id="Asia/Jakarta",
            ignore_https_errors=True,
        )
        page = context.new_page()
        client: CDPSession = context.new_cdp_session(page)
        try:
            client.send("Profiler.enable")
            client.send("Profiler.startPreciseCoverage", {"detailed": True})

            code = TAINT_XSS_SCRIPT + ("\n" + inject_js if inject_js else "")
            page.add_init_script(code)

            try:
                page.goto(url, wait_until="load", timeout=timeout)
            except PWError:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout * 2)

            page.wait_for_timeout(1200)

            result = client.send("Profiler.takePreciseCoverage")
            client.send("Profiler.stopPreciseCoverage")
            client.send("Profiler.disable")

            for entry in (result or {}).get("result", []):
                for func in entry.get("functions", []):
                    for r in func.get("ranges", []):
                        try:
                            if r.get("count", 0) > 0:
                                total += 1
                        except Exception:
                            continue
        finally:
            try: page.close()
            except Exception: pass
            try: context.close()
            except Exception: pass
            try: browser.close()
            except Exception: pass

    return int(total)

