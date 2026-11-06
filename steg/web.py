"""Web app: encode/decode UI, metrics history, and an admin panel for feature flags."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import statistics
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from PIL import Image, ImageChops

from . import features
from .analysis import analyze
from .config import data_dir
from .core import StegError, capacity_bytes, decode, encode

COOKIE = "steg_admin"
_OUTPUT_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_FAILS: dict[str, list[float]] = {}
_FAIL_LOCK = __import__("threading").RLock()
_FAIL_LIMIT = 5
_FAIL_WINDOW = 60.0

CSS = """
:root{
  --chrome:#eef4f4; --sheet:#ffffff; --raised:#f5f8f8; --active:#e6eded;
  --border:#e2e8e8; --rule:#edf1f1; --control:#cbd5d5;
  --ink:#131a1a; --muted:#596565; --faint:#6b7777;
  --accent:#1b6c80; --accent-soft:#e2f0f2;
  --positive:#1e7b4f; --negative:#b4232a;
  --radius-card:8px; --radius-control:6px; --radius-sheet:16px;
  --font:"IBM Plex Sans",Inter,system-ui,-apple-system,"Segoe UI",sans-serif;
  --mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Consolas,monospace;
}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--chrome);color:var(--ink);font-family:var(--font);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
p{margin:0}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline;text-underline-offset:2px}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:3px}
::selection{background:var(--accent-soft)}
.skip{position:absolute;left:-9999px;top:8px;z-index:50;background:#fff;border:1px solid var(--control);border-radius:6px;padding:8px 12px}
.skip:focus{left:8px}
.frame{display:grid;grid-template-columns:228px minmax(0,1fr);min-height:100vh}
.sidebar{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:28px;padding:22px 16px 18px;background:var(--chrome)}
.brand{display:flex;align-items:center;gap:10px;padding:0 8px;color:var(--ink);font-size:15px;font-weight:600;letter-spacing:-.01em}
.brand:hover{text-decoration:none}
.brand svg{flex:none}
.side-nav{display:flex;flex-direction:column;gap:2px}
.nav-item{display:flex;align-items:center;gap:10px;height:36px;padding:0 10px;border-radius:6px;color:var(--muted);font-size:14px;font-weight:500;transition:background .12s ease,color .12s ease}
.nav-item svg{width:16px;height:16px;flex:none;color:var(--faint)}
.nav-item:hover{background:var(--active);color:var(--ink);text-decoration:none}
.nav-item.active{background:var(--active);color:var(--ink)}
.nav-item.active svg{color:var(--accent)}
.side-foot{margin-top:auto;padding:16px 10px 0;border-top:1px solid var(--border)}
.foot-label{margin:0 0 4px;font-size:12px;font-weight:600;color:var(--muted)}
.foot-note{margin:0;font-size:12px;line-height:1.6;color:var(--faint)}
.work{display:flex;flex-direction:column;min-width:0}
.topbar{flex:none;height:48px;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:0 24px;color:var(--muted);font-size:13px}
.crumb{overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.crumb .sep{margin:0 6px;color:#98a5a5}
.local{display:flex;align-items:center;gap:7px;white-space:nowrap;font-size:12px;color:var(--faint)}
.top-brand{display:none}
.dot{width:6px;height:6px;flex:none;border-radius:50%;background:var(--positive)}
.sheet{flex:1;min-width:0;margin:0 8px 8px 0;padding:32px;background:var(--sheet);border:1px solid var(--border);border-radius:var(--radius-sheet);min-height:calc(100vh - 56px)}
.page-head{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;margin-bottom:28px}
h1{margin:0 0 6px;font-size:24px;line-height:1.25;font-weight:600;letter-spacing:-.02em}
.lede{margin:0;max-width:64ch;color:var(--muted);font-size:14px}
.head-note{padding-top:5px;color:var(--faint);font-size:12px;white-space:nowrap}
h2{margin:0;font-size:16px;font-weight:600;letter-spacing:-.01em}
h3{margin:0;font-size:13px;font-weight:600}
.muted{color:var(--muted)}
.split{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:24px;align-items:start}
.panel{background:var(--sheet);border:1px solid var(--border);border-radius:var(--radius-card)}
.panel-head{padding:20px 24px 0}
.panel-head p{margin-top:4px;color:var(--muted);font-size:13px}
.panel-body{padding:20px 24px 24px}
.aside{display:flex;flex-direction:column;gap:16px}
.aside-panel{background:var(--raised)}
.aside-panel .panel-body{padding:20px}
.aside-caption{margin-top:6px;color:var(--muted);font-size:13px;line-height:1.55}
.field{margin-bottom:18px}
.field:last-of-type{margin-bottom:0}
.label-row{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:7px}
label,.field-label{font-size:13px;font-weight:500;color:var(--ink)}
.hint{color:var(--faint);font-size:12px;font-weight:400}
input[type=file],input[type=password],input[type=number],input[type=text],textarea{width:100%;min-height:40px;padding:9px 11px;font:inherit;font-size:14px;color:var(--ink);background:#fff;border:1px solid var(--control);border-radius:var(--radius-control);transition:border-color .12s ease}
textarea{min-height:132px;line-height:1.55;resize:vertical}
input[type=file]:hover,input[type=password]:hover,input[type=number]:hover,input[type=text]:hover,textarea:hover{border-color:#aebbbb}
input:focus,textarea:focus{outline:2px solid var(--accent);outline-offset:-1px;border-color:var(--accent)}
input[type=file]{padding:6px;color:var(--muted);font-size:13px}
input[type=file]::file-selector-button{margin-right:12px;padding:7px 12px;font:inherit;font-size:13px;font-weight:500;color:var(--ink);background:var(--active);border:1px solid var(--border);border-radius:4px;cursor:pointer}
input[type=file]::file-selector-button:hover{background:#dbe5e5}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:40px;padding:0 18px;font:inherit;font-size:14px;font-weight:500;color:#fff;background:var(--ink);border:1px solid transparent;border-radius:var(--radius-control);cursor:pointer;text-decoration:none;transition:background .12s ease}
.btn:hover{background:#000;text-decoration:none}
.btn:active{transform:translateY(1px)}
.btn.secondary{color:var(--ink);background:#fff;border-color:var(--control)}
.btn.secondary:hover{background:var(--raised)}
.btn-row{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-top:22px}
.form-note{margin-top:14px;color:var(--faint);font-size:12px;line-height:1.6}
.alert{padding:11px 14px;margin-bottom:18px;color:var(--negative);background:#fdf0f0;border:1px solid #f2d2d2;border-radius:var(--radius-control);font-size:13px}
.notice-ok{display:flex;align-items:center;gap:8px;padding:11px 14px;margin-bottom:20px;color:#145c3a;background:#e8f6ee;border:1px solid #c6e6d4;border-radius:var(--radius-control);font-size:13px}
.success{display:flex;align-items:center;gap:8px;color:var(--positive);font-size:13px;font-weight:500}
.success svg{flex:none}
.bit-grid{display:grid;grid-template-columns:repeat(16,1fr);gap:3px;max-width:460px;margin:16px 0 14px}
.bit{aspect-ratio:1;background:#d8e2e2;border-radius:1px}
.bit.on{background:var(--accent)}
.spec{display:flex;align-items:baseline;justify-content:space-between;gap:12px;padding:8px 0;border-top:1px solid var(--rule);font-size:13px}
.spec:first-of-type{padding-top:0;border-top:0}
.spec:last-of-type{padding-bottom:0}
.spec span{color:var(--muted)}
.spec b{font-weight:500;color:var(--ink);font-variant-numeric:tabular-nums}
.spec.total{padding-top:10px;margin-top:4px;border-top:1px solid var(--border)}
.spec.total span{color:var(--ink);font-weight:500}
.rules,.steps{margin:10px 0 0;padding-left:18px;color:var(--muted);font-size:13px;line-height:1.6}
.rules li,.steps li{margin-bottom:8px}
.rules li:last-child,.steps li:last-child{margin-bottom:0}
.steps li::marker{color:var(--accent);font-weight:500}
.kpis{display:grid;grid-template-columns:repeat(var(--cols,4),minmax(0,1fr));margin:22px 0 20px;background:var(--sheet);border:1px solid var(--border);border-radius:var(--radius-card);overflow:hidden}
.kpi{padding:16px 20px;border-left:1px solid var(--rule)}
.kpi:first-child{border-left:0}
.kpi-label{margin-bottom:5px;color:var(--muted);font-size:12px}
.kpi-value{font-size:26px;font-weight:400;line-height:1.15;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.kpi-value small{margin-left:3px;font-size:13px;font-weight:400;color:var(--muted)}
.meter{margin-top:2px}
.meter-head{display:flex;justify-content:space-between;gap:12px;margin-bottom:7px;color:var(--muted);font-size:12px}
.meter-head b{font-weight:500;color:var(--ink);font-variant-numeric:tabular-nums}
.meter-track{height:6px;background:var(--active);border-radius:999px;overflow:hidden}
.meter-fill{height:100%;min-width:2px;background:var(--accent);border-radius:999px}
.kpi-row{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:var(--gap);margin:4px 0 36px}
.kpi-row .kpi{padding:0;border:0}
.kpi-row .kpi-value{font-size:30px}
.section-head{display:flex;align-items:baseline;justify-content:space-between;gap:16px;margin-bottom:12px}
.section-head .hint{font-size:12px}
.table-wrap{overflow-x:auto}
table{width:100%;min-width:560px;border-collapse:collapse;font-size:13px}
thead th{padding:0 12px 9px;font-size:12px;font-weight:400;color:var(--muted);text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}
tbody td{padding:13px 12px;color:var(--ink);border-bottom:1px solid var(--rule)}
tbody tr:last-child td{border-bottom:0}
tbody td.time{color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}
.num{text-align:right;font-variant-numeric:tabular-nums}
thead th:first-child,tbody td:first-child{padding-left:0}
thead th:last-child,tbody td:last-child{padding-right:0}
.empty{padding:16px;color:var(--muted);font-size:13px;border:1px dashed var(--control);border-radius:var(--radius-card)}
.research-grid{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:24px;align-items:start;margin-top:36px;padding-top:24px;border-top:1px solid var(--border)}
.chart{display:flex;flex-direction:column;gap:10px;margin-top:16px}
.chart-row{display:grid;grid-template-columns:78px minmax(0,1fr) 68px;align-items:center;gap:12px}
.chart-time{font-family:var(--mono);font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}
.chart-track{height:8px;background:var(--active);border-radius:999px;overflow:hidden}
.chart-fill{height:100%;min-width:2px;background:var(--accent);border-radius:999px}
.chart-value{text-align:right;font-size:12px;color:var(--ink);font-variant-numeric:tabular-nums}
.defs-stack>div+div{margin-top:16px;padding-top:16px;border-top:1px solid var(--border)}
.defs-stack p{margin-top:4px;color:var(--muted);font-size:13px;line-height:1.6}
.explain{margin-top:32px;padding-top:24px;border-top:1px solid var(--border)}
.explain-head{display:flex;align-items:baseline;justify-content:space-between;gap:16px;margin-bottom:16px}
.explain-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:24px}
.explain h3{margin-bottom:4px;font-size:13px;font-weight:600}
.explain p{color:var(--muted);font-size:13px;line-height:1.6}
pre.message{margin:16px 0 0;padding:20px;min-height:110px;font-family:var(--font);font-size:15px;line-height:1.65;color:var(--ink);background:var(--raised);border:1px solid var(--border);border-radius:var(--radius-card);white-space:pre-wrap;word-break:break-word}
.mono{font-family:var(--mono)}
.login{max-width:440px;margin:24px auto 0}
.login .panel-body{padding:26px 26px 28px}
.login .lede{margin-bottom:22px}
.settings{display:flex;flex-direction:column}
.setting{display:grid;grid-template-columns:300px minmax(0,1fr);gap:24px;padding:26px 0;border-top:1px solid var(--border)}
.setting:first-child{padding-top:0;border-top:0}
.setting-copy p{margin-top:4px;color:var(--muted);font-size:13px;line-height:1.55}
.setting-panel{padding:6px 16px;background:var(--raised);border-radius:var(--radius-card)}
.switch-row{position:relative;display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:16px;padding:12px 0;border-top:1px solid var(--rule);cursor:pointer}
.switch-row:first-child{border-top:0}
.switch-copy b{display:block;font-size:13px;font-weight:500;color:var(--ink)}
.switch-copy span{display:block;margin-top:1px;color:var(--muted);font-size:12px}
.switch{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}
.track{position:relative;width:36px;height:20px;flex:none;background:#c4d0d0;border-radius:999px;transition:background .15s ease}
.track::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;background:#fff;border-radius:50%;transition:transform .15s ease}
.switch:checked + .track{background:var(--accent)}
.switch:checked + .track::after{transform:translateX(16px)}
.switch:focus-visible + .track{outline:2px solid var(--accent);outline-offset:2px}
.inline-field{display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap;padding:16px 0 12px;border-top:1px solid var(--rule)}
.inline-field .field-copy{min-width:200px;flex:1}
.inline-field label{display:block;margin-bottom:3px}
.inline-field .hint{display:block;margin-top:2px}
.input-suffix{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--muted)}
.input-suffix input{width:92px;min-height:36px}
.panel-actions{display:flex;justify-content:flex-end;padding:12px 0 14px}
.session-panel{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:16px}
.session-state{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--ink)}
.session-panel form{margin:0}
select{width:100%;min-height:40px;padding:9px 11px;font:inherit;font-size:14px;color:var(--ink);background:#fff;border:1px solid var(--control);border-radius:var(--radius-control)}
.drop{border:1px dashed var(--control);border-radius:var(--radius-control);padding:10px;transition:border-color .12s ease,background .12s ease}
.drop.dragover{border-color:var(--accent);background:var(--accent-soft)}
.capacity{margin-top:8px;color:var(--muted);font-size:12px}
.strength{margin-top:8px}
.strength-track{height:4px;background:var(--active);border-radius:999px;overflow:hidden}
.strength-fill{height:100%;width:0;background:var(--negative);border-radius:999px;transition:width .15s ease,background .15s ease}
.strength-label{display:block;margin-top:5px;color:var(--faint);font-size:12px}
.compare{position:relative;max-width:640px;margin:12px 0 4px;border:1px solid var(--border);border-radius:var(--radius-card);overflow:hidden;background:var(--raised)}
.compare>img{display:block;width:100%}
.compare .top{position:absolute;inset:0;clip-path:inset(0 50% 0 0)}
.compare-tag{position:absolute;top:8px;padding:2px 6px;font-size:11px;color:#fff;background:rgba(0,0,0,.65);border-radius:4px;pointer-events:none}
.compare-tag.left{left:8px}
.compare-tag.right{right:8px}
.compare input[type=range]{display:block;width:calc(100% - 24px);margin:10px 12px}
.diff-img{display:block;max-width:640px;width:100%;margin-top:10px;background:#000;border:1px solid var(--border);border-radius:var(--radius-card)}
.verdict{margin:18px 0;padding:14px 16px;background:var(--raised);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:var(--radius-control);font-size:13px;line-height:1.6}
.badge{display:inline-block;padding:2px 8px;font-size:11px;font-weight:600;letter-spacing:.02em;border-radius:999px}
.badge.hit{color:#7a1f1f;background:#fbe4e4}
.badge.clean{color:#145c3a;background:#e2f3ea}
.report-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin:18px 0}
.report-card{padding:18px;background:var(--raised);border:1px solid var(--border);border-radius:var(--radius-card)}
.report-card h3{margin-bottom:10px}
@media (max-width:640px){.report-grid{grid-template-columns:1fr}}
input[type=range]{accent-color:var(--accent)}
body,p,li,td,th,label,button,input,textarea{font-feature-settings:"ss01" 0}
@media (max-width:1120px){
  .split{grid-template-columns:1fr}
  .aside{display:grid;grid-template-columns:1fr 1fr}
  .research-grid{grid-template-columns:1fr}
  .setting{grid-template-columns:240px minmax(0,1fr)}
}
@media (max-width:900px){
  .frame{grid-template-columns:200px minmax(0,1fr)}
  .sheet{padding:24px}
  .kpi-row{grid-template-columns:repeat(2,minmax(0,1fr));row-gap:24px}
  .defs{grid-template-columns:1fr;gap:18px}
  .setting{grid-template-columns:1fr;gap:10px}
  .explain-grid{grid-template-columns:1fr;gap:16px}
}
@media (max-width:880px){
  .frame{display:block}
  .sidebar{position:fixed;top:auto;right:0;bottom:0;left:0;z-index:20;height:auto;min-height:64px;flex-direction:row;align-items:center;padding:6px 8px calc(6px + env(safe-area-inset-bottom));border-top:1px solid var(--border);background:var(--chrome)}
  .brand,.side-foot{display:none}
  .side-nav{flex:1;flex-direction:row;gap:0;justify-content:space-around}
  .nav-item{flex:1;flex-direction:column;gap:3px;height:auto;min-height:50px;justify-content:center;padding:6px 4px;font-size:11px;border-radius:8px}
  .nav-item svg{width:18px;height:18px}
  .work{min-height:100vh}
  .topbar{height:44px;padding:0 16px}
  .top-brand{display:flex;align-items:center;gap:8px;color:var(--ink);font-size:14px;font-weight:600}
  .top-brand:hover{text-decoration:none}
  .top-brand svg{width:22px;height:22px}
  .crumb,.local{display:none}
  .sheet{margin:0 8px 80px;padding:22px 18px 26px;border-radius:12px;min-height:0}
  .page-head{flex-direction:column;gap:6px;margin-bottom:22px}
  h1{font-size:22px}
  .head-note{padding-top:0}
  .aside{grid-template-columns:1fr}
  .kpi{padding:14px 16px}
  .kpi-value{font-size:23px}
  .kpi-row{grid-template-columns:1fr 1fr;gap:20px;margin-bottom:30px}
  .kpi-row .kpi-value{font-size:26px}
  .kpi-row .kpi:nth-child(3){padding-left:0}
  .setting-panel{padding:4px 14px}
  .login{margin-top:8px}
  .btn-row{flex-direction:column;align-items:stretch}
  .btn-row .btn{width:100%}
  .panel-actions{justify-content:stretch}
  .panel-actions .btn{width:100%}
}
@media (max-width:520px){
  .kpis{grid-template-columns:1fr 1fr}
  .kpi{padding:14px 14px}
  .kpi:nth-child(3){border-left:0;border-top:1px solid var(--rule)}
  .kpi:nth-child(4){border-top:1px solid var(--rule)}
  .kpi-value{font-size:22px}
  .session-panel{flex-direction:column;align-items:flex-start}
  .session-panel .btn{width:100%}
  .inline-field{flex-direction:column;gap:10px}
}
@media (max-width:640px){
  .table-wrap{overflow:visible}
  table{display:block;min-width:0}
  thead{display:none}
  tbody{display:block}
  tbody tr{display:block;padding:12px 0;border-bottom:1px solid var(--rule)}
  tbody tr:last-child{border-bottom:0}
  tbody td{display:flex;align-items:baseline;justify-content:space-between;gap:16px;padding:3px 0;border:0;text-align:right}
  tbody td::before{content:attr(data-label);color:var(--muted);font-size:12px;text-align:left}
  tbody td:first-child,tbody td:last-child{padding-right:0;padding-left:0}
}
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{transition:none !important;animation:none !important}
}
"""

ENCODE_JS = """
(function(){
  var input=document.getElementById('image');
  var drop=document.getElementById('drop');
  var cap=document.getElementById('capacity');
  var pw=document.getElementById('password');
  var fill=document.getElementById('strength-fill');
  var label=document.getElementById('strength-label');
  function readable(n){
    if(n>=1048576)return (n/1048576).toFixed(2)+' MB';
    if(n>=1024)return (n/1024).toFixed(1)+' KB';
    return n+' B';
  }
  function updateCapacity(){
    var file=input.files&&input.files[0];
    if(!file){cap.textContent='Choose an image to see its capacity.';return;}
    var url=URL.createObjectURL(file);
    var img=new Image();
    img.onload=function(){
      var raw=Math.floor(img.width*img.height*3/8);
      var usable=Math.max(0,raw-49);
      cap.textContent=img.width+' × '+img.height+' px · about '+readable(usable)+' of payload space after 49 B overhead';
      URL.revokeObjectURL(url);
    };
    img.onerror=function(){cap.textContent='Could not read that image.';URL.revokeObjectURL(url);};
    img.src=url;
  }
  function updateStrength(){
    var v=pw.value,score=0;
    if(v.length>=4)score++;
    if(v.length>=8)score++;
    if(v.length>=12)score++;
    if(/[^A-Za-z0-9]/.test(v))score++;
    if(/[A-Z]/.test(v)&&/[a-z]/.test(v))score++;
    var levels=[['Too short','var(--negative)',0],['Weak','var(--negative)',20],['Fair','#b07a12',40],['Good','var(--accent)',65],['Strong','var(--positive)',85],['Very strong','var(--positive)',100]];
    var level=levels[score];
    fill.style.width=(v?level[2]:0)+'%';
    fill.style.background=level[1];
    label.textContent=v?level[0]:'Use at least 12 characters for a strong password.';
  }
  if(input){
    input.addEventListener('change',updateCapacity);
    if(drop){
      ['dragenter','dragover'].forEach(function(ev){drop.addEventListener(ev,function(e){e.preventDefault();drop.classList.add('dragover');});});
      ['dragleave','drop'].forEach(function(ev){drop.addEventListener(ev,function(e){e.preventDefault();drop.classList.remove('dragover');});});
      drop.addEventListener('drop',function(e){
        if(e.dataTransfer.files.length){input.files=e.dataTransfer.files;updateCapacity();}
      });
    }
  }
  if(pw){pw.addEventListener('input',updateStrength);updateStrength();}
})();
"""

NAV_ITEMS = [
    ("/", "Encode", "encode"),
    ("/decode", "Decode", "decode"),
    ("/detect", "Detect", "detect"),
    ("/research", "Research", "research"),
    ("/admin", "Admin", "admin"),
]

ICONS = {
    "encode": '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 2v7"/><path d="m5.2 6.5 2.8 2.8 2.8-2.8"/><path d="M2.5 10.5v1.8a1.2 1.2 0 0 0 1.2 1.2h8.6a1.2 1.2 0 0 0 1.2-1.2v-1.8"/></svg>',
    "decode": '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 13V6"/><path d="m5.2 8.5 2.8-2.8 2.8 2.8"/><path d="M2.5 5.5V3.7a1.2 1.2 0 0 1 1.2-1.2h8.6a1.2 1.2 0 0 1 1.2 1.2v1.8"/></svg>',
    "detect": '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="7" cy="7" r="4.2"/><path d="m10.2 10.2 3.3 3.3"/></svg>',
    "research": '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2.5 13.5h11"/><path d="M4 13V9"/><path d="M8 13V5"/><path d="M12 13V7"/></svg>',
    "admin": '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 5h6"/><circle cx="11" cy="5" r="1.6"/><path d="M14 11H8"/><circle cx="5" cy="11" r="1.6"/></svg>',
}

MARK = """<svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true">
<rect width="28" height="28" rx="7" fill="#131a1a"/>
<g fill="#e9f1f1">
<rect x="6" y="6" width="4" height="4"/><rect x="12" y="6" width="4" height="4"/><rect x="18" y="6" width="4" height="4"/>
<rect x="6" y="12" width="4" height="4"/><rect x="12" y="12" width="4" height="4"/>
<rect x="6" y="18" width="4" height="4"/><rect x="12" y="18" width="4" height="4"/>
</g>
<rect x="18" y="12" width="4" height="4" fill="#4fb3c4"/>
</svg>"""

CHECK = '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m3 8.5 3.2 3L13 4.5"/></svg>'


@asynccontextmanager
async def lifespan(_: FastAPI):
    if not os.environ.get("ADMIN_PASSWORD"):
        print("[steg] ADMIN_PASSWORD not set; admin password defaults to 1234.", flush=True)
    yield


app = FastAPI(title="Stegano", lifespan=lifespan)


def _esc(value) -> str:
    return html.escape(str(value))


def _nav(active: str) -> str:
    flags = features.load()
    links = []
    for href, label, key in NAV_ITEMS:
        if key == "detect" and not flags["detection_enabled"]:
            continue
        current = ' aria-current="page"' if key == active else ""
        css = "nav-item active" if key == active else "nav-item"
        links.append(f'<a class="{css}" href="{href}"{current}>{ICONS[key]}<span>{label}</span></a>')
    return "".join(links)


def page(title: str, body: str, status_code: int = 200, active: str = "") -> HTMLResponse:
    return HTMLResponse(
        f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)} · Stegano</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>{CSS}</style></head>
<body>
<a class="skip" href="#main">Skip to content</a>
<div class="frame">
<aside class="sidebar">
  <a class="brand" href="/">{MARK}<span>Stegano</span></a>
  <nav class="side-nav" aria-label="Primary">{_nav(active)}</nav>
  <div class="side-foot">
    <p class="foot-label">Local workbench</p>
    <p class="foot-note">AES-256-GCM<br>PNG / BMP output</p>
  </div>
</aside>
<div class="work">
  <header class="topbar">
    <a class="top-brand" href="/">{MARK}<span>Stegano</span></a>
    <span class="crumb">Workbench<span class="sep">/</span>{_esc(title)}</span>
    <span class="local"><span class="dot"></span>Processed on this server</span>
  </header>
  <main class="sheet" id="main">{body}</main>
</div>
</div>
</body></html>""",
        status_code=status_code,
    )


def _admin_password() -> str:
    return os.environ.get("ADMIN_PASSWORD") or "1234"


def _admin_cookie() -> str:
    return hashlib.sha256(f"steg-admin:{_admin_password()}".encode("utf-8")).hexdigest()


def _is_admin(request: Request) -> bool:
    return hmac.compare_digest(request.cookies.get(COOKIE, ""), _admin_cookie())


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _blocked(request: Request) -> bool:
    now = time.monotonic()
    with _FAIL_LOCK:
        recent = [stamp for stamp in _FAILS.get(_client_ip(request), []) if now - stamp < _FAIL_WINDOW]
        _FAILS[_client_ip(request)] = recent
        return len(recent) >= _FAIL_LIMIT


def _fail_login(request: Request) -> None:
    with _FAIL_LOCK:
        _FAILS.setdefault(_client_ip(request), []).append(time.monotonic())


def _clear_fails(request: Request) -> None:
    with _FAIL_LOCK:
        _FAILS.pop(_client_ip(request), None)


def _disabled(title: str, active: str) -> HTMLResponse:
    body = f"""<div class="page-head">
  <div><h1>{_esc(title)} unavailable</h1>
  <p class="lede">An administrator has turned this feature off for this workbench.</p></div>
</div>
<div class="panel"><div class="panel-body">
  <p class="muted">Feature flags are managed from the admin panel.</p>
  <div class="btn-row"><a class="btn secondary" href="/">Back to workbench</a></div>
</div></div>"""
    return page(title, body, 403, active)


def _bit_grid(lit: int = 22) -> str:
    pattern = {0, 1, 3, 7, 8, 14, 15, 21, 22, 27, 28, 35, 36, 44, 50, 57, 63, 64, 72, 79, 85, 86, 93}
    cells = []
    for index in range(96):
        cells.append('<span class="bit on"></span>' if index in pattern else '<span class="bit"></span>')
    return "".join(cells)


def _data_url(img: Image.Image) -> str:
    preview = img.copy()
    preview.thumbnail((640, 640))
    buffer = io.BytesIO()
    preview.save(buffer, "PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


def _diff_map(cover: Image.Image, stego: Image.Image) -> str:
    left, right = cover.copy(), stego.copy()
    left.thumbnail((640, 640))
    right.thumbnail((640, 640))
    diff = ImageChops.difference(left, right).point(lambda value: min(255, value * 64))
    buffer = io.BytesIO()
    diff.save(buffer, "PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


def _encode_form(error: str = "") -> str:
    alert = f'<div class="alert" role="alert">{_esc(error)}</div>' if error else ""
    return f"""<div class="page-head">
  <div><h1>Encode</h1>
  <p class="lede">Hide an AES-256-GCM message in password-scattered least significant bits of a PNG or BMP.</p></div>
  <span class="head-note">PNG / BMP · 49 B overhead</span>
</div>
<div class="split">
<section class="panel" aria-labelledby="cover-title">
  <div class="panel-head">
    <h2 id="cover-title">Cover and message</h2>
    <p>Encrypted and compressed first, then scattered by a password-keyed sequence.</p>
  </div>
  <div class="panel-body">
    {alert}
    <form id="encode-form" method="post" action="/encode" enctype="multipart/form-data">
      <div class="field">
        <div class="label-row"><label for="image">Cover image</label><span class="hint">PNG or BMP</span></div>
        <div class="drop" id="drop">
          <input id="image" type="file" name="image" accept="image/png,image/bmp,image/*" required>
          <p class="capacity" id="capacity">Choose an image to see its capacity.</p>
        </div>
      </div>
      <div class="field">
        <div class="label-row"><label for="message">Secret message</label><span class="hint">UTF-8 text, compressed when smaller</span></div>
        <textarea id="message" name="message" rows="5" required></textarea>
      </div>
      <div class="field">
        <div class="label-row"><label for="password">Password</label><span class="hint" id="password-hint">Keys scrypt and AES</span></div>
        <input id="password" type="password" name="password" minlength="4" required aria-describedby="password-hint strength-label">
        <div class="strength">
          <div class="strength-track"><div class="strength-fill" id="strength-fill"></div></div>
          <span class="strength-label" id="strength-label"></span>
        </div>
      </div>
      <div class="field">
        <div class="label-row"><label for="fmt">Output format</label><span class="hint">BMP is uncompressed and larger</span></div>
        <select id="fmt" name="fmt">
          <option value="PNG" selected>PNG (recommended)</option>
          <option value="BMP">BMP (lossless, larger)</option>
        </select>
      </div>
      <div class="btn-row">
        <button class="btn" type="submit">Encrypt and embed</button>
        <span class="hint">Processed by this server, not a third party.</span>
      </div>
    </form>
  </div>
</section>
<aside class="aside" aria-label="Payload reference">
  <section class="panel aside-panel">
    <div class="panel-body">
      <h2>Payload format</h2>
      <p class="aside-caption">The message and header are scattered across a keyed sample of RGB channels. Lit squares show touched channels, not byte order.</p>
      <div class="bit-grid" role="img" aria-label="Channel map diagram: payload bits are scattered across sampled RGB channels">{_bit_grid()}</div>
      <div class="specs">
        <div class="spec"><span>scrypt salt</span><b>16 B</b></div>
        <div class="spec"><span>GCM nonce</span><b>12 B</b></div>
        <div class="spec"><span>Message length</span><b>4 B</b></div>
        <div class="spec"><span>Flags</span><b>1 B</b></div>
        <div class="spec"><span>GCM tag</span><b>16 B</b></div>
        <div class="spec total"><span>Fixed overhead</span><b>49 B</b></div>
      </div>
    </div>
  </section>
  <section class="panel aside-panel">
    <div class="panel-body">
      <h2>Rules of the format</h2>
      <ul class="rules">
        <li>No magic bytes: the header position is derived from your password.</li>
        <li>Bits are scattered, never written in sequence. LSB matching moves a channel by at most one.</li>
        <li>Unused low bits are filled with random noise, so the whole plane looks touched.</li>
        <li>Output stays lossless. Resizing or JPEG re-saving destroys the payload.</li>
        <li>Capacity is width × height × 3 ÷ 8 bytes before overhead.</li>
      </ul>
    </div>
  </section>
</aside>
</div>
<section class="explain" aria-labelledby="process-title">
  <div class="explain-head"><h2 id="process-title">What happens on submit</h2><span class="hint">Encryption happens before any pixel is touched</span></div>
  <div class="explain-grid">
    <div><h3>Key derivation</h3><p>scrypt (N=2¹⁴, r=8, p=1) stretches the password, then HKDF derives a per-image encryption key and scatter seed.</p></div>
    <div><h3>Scatter and match</h3><p>AES-256-GCM seals the message. Each bit is written to a keyed channel position with LSB matching instead of replacement.</p></div>
    <div><h3>Noise fill</h3><p>Every untouched low bit is randomised, so textured and flat regions carry a similarly noisy LSB plane.</p></div>
  </div>
</section>
<script>{ENCODE_JS}</script>"""


def _decode_form(error: str = "") -> str:
    alert = f'<div class="alert" role="alert">{_esc(error)}</div>' if error else ""
    return f"""<div class="page-head">
  <div><h1>Decode</h1>
  <p class="lede">Recover and decrypt a message from a stego PNG.</p></div>
  <span class="head-note">AES-256-GCM</span>
</div>
<div class="split">
<section class="panel" aria-labelledby="stego-title">
  <div class="panel-head">
    <h2 id="stego-title">Stego image</h2>
    <p>Upload the file exactly as it was downloaded and enter the original password.</p>
  </div>
  <div class="panel-body">
    {alert}
    <form method="post" action="/decode" enctype="multipart/form-data">
      <div class="field">
        <div class="label-row"><label for="image">Stego image</label><span class="hint">PNG or BMP</span></div>
        <input id="image" type="file" name="image" accept="image/*" required>
      </div>
      <div class="field">
        <div class="label-row"><label for="password">Password</label><span class="hint">Same as encode</span></div>
        <input id="password" type="password" name="password" required>
      </div>
      <div class="btn-row">
        <button class="btn" type="submit">Decrypt and extract</button>
      </div>
    </form>
  </div>
</section>
<aside class="aside" aria-label="Extraction notes">
  <section class="panel aside-panel">
    <div class="panel-body">
      <h2>Before you upload</h2>
      <ul class="rules">
        <li>Use the file exactly as it was downloaded.</li>
        <li>Resizing, screenshots, or JPEG conversion remove the least significant bits.</li>
        <li>A wrong password fails authentication rather than returning garbage.</li>
      </ul>
    </div>
  </section>
  <section class="panel aside-panel">
    <div class="panel-body">
      <h2>Extraction order</h2>
      <ol class="steps">
        <li>Derive the master key from your password with scrypt.</li>
        <li>Sample the keyed header positions and read salt, nonce, and length.</li>
        <li>Read the scattered ciphertext and verify the GCM authentication tag.</li>
      </ol>
    </div>
  </section>
</aside>
</div>
<section class="explain" aria-labelledby="failure-title">
  <div class="explain-head"><h2 id="failure-title">How failures are reported</h2><span class="hint">An invalid payload never returns partial output</span></div>
  <div class="explain-grid">
    <div><h3>Wrong password</h3><p>The GCM tag fails to verify, so the decoder reports a bad password instead of returning garbage.</p></div>
    <div><h3>Damaged file</h3><p>Resizing, compression, or edits break the embedded bits; extraction stops at the length check or the tag.</p></div>
    <div><h3>No payload</h3><p>An ordinary image has no keyed header, so it is rejected as <span class="mono">no hidden message found, or wrong password</span>.</p></div>
  </div>
</section>"""


def _login_form(error: str = "") -> str:
    alert = f'<div class="alert" role="alert">{_esc(error)}</div>' if error else ""
    return f"""<div class="login">
<section class="panel">
  <div class="panel-body">
    <h1>Admin login</h1>
    <p class="lede">Enter the admin password. Set <span class="mono">ADMIN_PASSWORD</span> to change it from the default <span class="mono">1234</span>.</p>
    {alert}
    <form method="post" action="/admin/login">
      <div class="field">
        <div class="label-row"><label for="password">Password</label></div>
        <input id="password" type="password" name="password" required autofocus>
      </div>
      <div class="btn-row"><button class="btn" type="submit">Log in</button></div>
    </form>
    <p class="form-note">Five failed attempts from one address lock login for a minute.</p>
  </div>
</section>
</div>"""


def _kpi(label: str, value: str) -> str:
    return f'<div class="kpi"><p class="kpi-label">{_esc(label)}</p><p class="kpi-value">{value}</p></div>'


def _num(value, digits: int = 0, suffix: str = "") -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "—"
    return f"{value:,.{digits}f}{suffix}"


def _switch(name: str, title: str, description: str, checked: bool) -> str:
    return f"""<label class="switch-row">
  <span class="switch-copy"><b>{_esc(title)}</b><span>{_esc(description)}</span></span>
  <input class="switch" type="checkbox" name="{name}"{' checked' if checked else ''}>
  <span class="track" aria-hidden="true"></span>
</label>"""


def _admin_body(flags: dict, notice: str = "", error: str = "") -> str:
    alert = f'<div class="alert" role="alert">{_esc(error)}</div>' if error else notice
    body = f"""<div class="page-head">
  <div><h1>Admin</h1>
  <p class="lede">Feature flags apply immediately to every request on this workbench.</p></div>
</div>
{alert}
<form class="settings" method="post" action="/admin/flags">
  <div class="setting">
    <div class="setting-copy">
      <h2>Features</h2>
      <p>Turning a screen off returns a 403 for that surface while leaving the rest of the workbench running.</p>
      <p class="form-note">Stored in <span class="mono">data/features.json</span> on the server.</p>
    </div>
    <div class="setting-panel">
      {_switch("encode_enabled", "Embedding", "Encode page and new payloads", flags["encode_enabled"])}
      {_switch("decode_enabled", "Extraction", "Decode page and payload recovery", flags["decode_enabled"])}
      {_switch("detection_enabled", "Detector", "Chi-square analysis and before/after self-test", flags["detection_enabled"])}
      {_switch("diff_enabled", "Diff and slider", "Amplified difference map and before/after slider", flags["diff_enabled"])}
      {_switch("noise_fill_enabled", "Noise fill", "Randomise unused low bits on new encodes", flags["noise_fill_enabled"])}
      {_switch("metrics_enabled", "Quality metrics", "PSNR and MSE on results and research", flags["metrics_enabled"])}
      {_switch("research_enabled", "Research dashboard", "Recorded encode history and table", flags["research_enabled"])}
      <div class="inline-field">
        <div class="field-copy">
          <label for="max_upload_mb">Maximum upload size</label>
          <span class="hint" id="upload-hint">1–50 MB, applied to both encode and decode uploads.</span>
        </div>
        <div class="input-suffix">
          <input id="max_upload_mb" type="number" name="max_upload_mb" min="1" max="50" value="{flags['max_upload_mb']}" required aria-describedby="upload-hint">
          <span>MB</span>
        </div>
      </div>
      <div class="panel-actions"><button class="btn" type="submit">Save changes</button></div>
    </div>
  </div>
</form>
<div class="setting">
  <div class="setting-copy">
    <h2>Session</h2>
    <p>This browser stays signed in for eight hours. The cookie is HttpOnly and SameSite=Lax.</p>
    <p class="form-note">Password source: <span class="mono">ADMIN_PASSWORD</span>, default <span class="mono">1234</span>. Five failed attempts per address trigger a 60-second lock.</p>
  </div>
  <div class="setting-panel session-panel">
    <span class="session-state"><span class="dot"></span>Signed in as admin</span>
    <form method="post" action="/admin/logout">
      <button class="btn secondary" type="submit">Log out</button>
    </form>
  </div>
</div>"""
    return body


@app.get("/", response_class=HTMLResponse)
def home():
    if not features.load()["encode_enabled"]:
        return _disabled("Encoder", "encode")
    return page("Encode", _encode_form(), active="encode")


@app.post("/encode", response_class=HTMLResponse)
async def do_encode(
    image: UploadFile = File(...),
    message: str = Form(...),
    password: str = Form(...),
    fmt: str = Form("PNG"),
):
    flags = features.load()
    if not flags["encode_enabled"]:
        return _disabled("Encoder", "encode")
    if not message.strip():
        return page("Encode", _encode_form("message must not be empty"), 400, "encode")
    if len(password) < 4:
        return page("Encode", _encode_form("password must be at least 4 characters"), 400, "encode")

    fmt = fmt.upper()
    try:
        raw = await _read_upload(image, flags["max_upload_mb"])
        result, stats = encode(
            raw, message, password, fmt=fmt, noise=flags["noise_fill_enabled"]
        )
    except (StegError, ValueError) as exc:
        return page("Encode", _encode_form(str(exc)), 400, "encode")

    output_id = secrets.token_urlsafe(9)
    ext = "bmp" if stats["format"] == "BMP" else "png"
    if os.environ.get("VERCEL"):
        # Serverless instances do not share /tmp, so inline the image in the download link.
        download_href = f"data:image/{ext};base64," + base64.b64encode(result).decode("ascii")
    else:
        outputs = data_dir() / "outputs"
        outputs.mkdir(parents=True, exist_ok=True)
        (outputs / f"{output_id}.{ext}").write_bytes(result)
        download_href = f"/download/{output_id}"
    detection = analyze(result) if flags["detection_enabled"] else None
    _record(stats, detected=bool(detection and detection["flagged"]))

    cols = 4 if flags["metrics_enabled"] else 2
    quality = ""
    if flags["metrics_enabled"]:
        quality = _kpi("PSNR", f'{stats["psnr_db"]}<small>dB</small>') + _kpi(
            "MSE", f'{stats["mse"]}'
        )
    quality_explain = (
        f"<div><h3>Visual quality</h3><p>{stats['psnr_db']} dB PSNR means the modified pixels are close to the cover. Above 40 dB is generally considered visually lossless.</p></div>"
        if flags["metrics_enabled"]
        else "<div><h3>Visual quality</h3><p>Quality metrics are turned off by the administrator.</p></div>"
    )

    compare = ""
    if flags["diff_enabled"]:
        cover_img = Image.open(io.BytesIO(raw)).convert("RGB")
        stego_img = Image.open(io.BytesIO(result)).convert("RGB")
        compare = f"""<section class="explain" aria-labelledby="compare-title">
  <div class="explain-head"><h2 id="compare-title">Before and after</h2><span class="hint">Drag the slider</span></div>
  <div class="compare">
    <img src="{_data_url(cover_img)}" alt="Cover image">
    <img class="top" id="compare-top" src="{_data_url(stego_img)}" alt="Stego image">
    <span class="compare-tag left">Cover</span>
    <span class="compare-tag right">Stego</span>
  </div>
  <input type="range" min="0" max="100" value="50" style="width:100%;margin-top:10px" aria-label="Reveal cover or stego" oninput="document.getElementById('compare-top').style.clipPath='inset(0 '+(100-this.value)+'% 0 0)'">
  <div class="section-head" style="margin-top:24px"><h3>Amplified difference</h3><span class="hint">Absolute difference ×64</span></div>
  <img class="diff-img" src="{_diff_map(cover_img, stego_img)}" alt="Difference map amplified 64 times; dark pixels are untouched">
  <p class="aside-caption">Single-step LSB changes are amplified 64× so they become visible. Dark areas are untouched.</p>
</section>"""

    body = f"""<div class="page-head">
  <div><h1>Message hidden</h1>
  <p class="lede">The ciphertext is scattered across keyed least significant bits, with LSB matching and noise fill.</p></div>
  <span class="head-note">{stats["format"]} · AES-256-GCM</span>
</div>
<div class="split">
  <div>
    <p class="success">{CHECK} Encrypted and embedded</p>
    <div class="kpis" style="--cols:{cols}">
      {_kpi("Message size", f'{stats["message_bytes"]:,}<small>B</small>')}
      {_kpi("Capacity used", f'{stats["fill_percent"]}<small>%</small>')}
      {quality}
    </div>
    <div class="meter">
      <div class="meter-head"><span>Payload footprint</span><b>{stats["payload_bytes"]:,} of {stats["capacity_bytes"]:,} B</b></div>
      <div class="meter-track" role="img" aria-label="Payload uses {stats['fill_percent']} percent of the image capacity"><div class="meter-fill" style="width:{min(stats['fill_percent'], 100)}%"></div></div>
    </div>
    <div class="btn-row">
      <a class="btn" href="{download_href}" download="stego-{output_id}.{ext}">Download stego {stats["format"]}</a>
      <a class="btn secondary" href="/decode">Decode an image</a>
    </div>
    <p class="form-note">Keep the file untouched. Any resize or JPEG conversion removes the payload.</p>
  </div>
  <aside class="aside" aria-label="File details">
    <section class="panel aside-panel">
      <div class="panel-body">
        <h2>File</h2>
        <div class="specs">
          <div class="spec"><span>Image</span><b>{stats["width"]} × {stats["height"]}</b></div>
          <div class="spec"><span>Output</span><b>{stats["format"]}</b></div>
          <div class="spec"><span>Payload</span><b>{stats["payload_bytes"]:,} B</b></div>
          <div class="spec"><span>Compressed</span><b>{"yes" if stats["compressed"] else "no"}</b></div>
          <div class="spec"><span>Noise fill</span><b>{"on" if stats["noise"] else "off"}</b></div>
          <div class="spec"><span>Raw capacity</span><b>{stats["capacity_bytes"]:,} B</b></div>
        </div>
        <p class="form-note">File name: <span class="mono">stego-{output_id}.{ext}</span></p>
      </div>
    </section>
  </aside>
</div>
{compare}
<section class="explain" aria-labelledby="result-reading">
  <div class="explain-head"><h2 id="result-reading">Reading the result</h2><span class="hint">Measured on the cover and stego pair</span></div>
  <div class="explain-grid">
    <div><h3>Payload footprint</h3><p>{stats["payload_bytes"]:,} bytes of header and ciphertext occupy {stats["fill_percent"]}% of the image's raw capacity.</p></div>
    {quality_explain}
    <div><h3>Keep it lossless</h3><p>PNG and BMP preserve the bits. Resizing, screenshotting, or re-saving as JPEG removes the payload.</p></div>
  </div>
</section>"""
    return page("Encode", body, active="encode")


@app.get("/decode", response_class=HTMLResponse)
def decode_page():
    if not features.load()["decode_enabled"]:
        return _disabled("Decoder", "decode")
    return page("Decode", _decode_form(), active="decode")


@app.post("/decode", response_class=HTMLResponse)
async def do_decode(
    image: UploadFile = File(...),
    password: str = Form(...),
):
    flags = features.load()
    if not flags["decode_enabled"]:
        return _disabled("Decoder", "decode")
    try:
        raw = await _read_upload(image, flags["max_upload_mb"])
        message = decode(raw, password)
    except (StegError, ValueError) as exc:
        return page("Decode", _decode_form(str(exc)), 400, "decode")

    try:
        text = _esc(message.decode("utf-8"))
    except UnicodeDecodeError:
        return page(
            "Decode",
            _decode_form("message is binary data, not text; use the CLI with -o to extract it"),
            400,
            "decode",
        )
    body = f"""<div class="page-head">
  <div><h1>Hidden message</h1>
  <p class="lede">Decrypted with AES-256-GCM. The authentication tag is valid.</p></div>
  <span class="head-note">UTF-8 · {len(message):,} B</span>
</div>
<div class="split">
  <section class="panel" aria-labelledby="message-title">
    <div class="panel-head">
      <h2 id="message-title">Message</h2>
      <p>Extracted from keyed positions scattered across the RGB channels.</p>
    </div>
    <div class="panel-body">
      <pre class="message">{text}</pre>
      <p class="form-note">Decoded {len(message):,} bytes of UTF-8 text.</p>
    </div>
  </section>
  <aside class="aside" aria-label="Extraction details">
    <section class="panel aside-panel">
      <div class="panel-body">
        <h2>Verification</h2>
        <div class="specs">
          <div class="spec"><span>Key derivation</span><b>scrypt</b></div>
          <div class="spec"><span>Integrity</span><b>GCM tag valid</b></div>
          <div class="spec"><span>Layout</span><b>keyed scatter</b></div>
          <div class="spec"><span>Encoding</span><b>UTF-8</b></div>
          <div class="spec"><span>Payload</span><b>{len(message):,} B</b></div>
        </div>
        <div class="btn-row"><a class="btn secondary" href="/decode">Decode another</a></div>
      </div>
    </section>
  </aside>
</div>"""
    return page("Decode", body, active="decode")


def _detect_form(error: str = "") -> str:
    alert = f'<div class="alert" role="alert">{_esc(error)}</div>' if error else ""
    return f"""<div class="page-head">
  <div><h1>Detector</h1>
  <p class="lede">Run a chi-square LSB-pair test and a legacy header scan against any image.</p></div>
  <span class="head-note">Chi-square · header scan</span>
</div>
<div class="split">
<section class="panel" aria-labelledby="detect-title">
  <div class="panel-head">
    <h2 id="detect-title">Image under test</h2>
    <p>Upload any image. Add a message and password to embed a fresh payload in memory and compare before and after.</p>
  </div>
  <div class="panel-body">
    {alert}
    <form method="post" action="/detect" enctype="multipart/form-data">
      <div class="field">
        <div class="label-row"><label for="image">Image</label><span class="hint">PNG or BMP</span></div>
        <input id="image" type="file" name="image" accept="image/png,image/bmp,image/*" required>
      </div>
      <div class="field">
        <div class="label-row"><label for="message">Test message</label><span class="hint">Optional: embed, then re-test</span></div>
        <textarea id="message" name="message" rows="3" placeholder="Leave empty to analyse the uploaded image as-is"></textarea>
      </div>
      <div class="field">
        <div class="label-row"><label for="password">Test password</label><span class="hint">Required with a message</span></div>
        <input id="password" type="password" name="password">
      </div>
      <div class="btn-row">
        <button class="btn" type="submit">Run analysis</button>
      </div>
    </form>
  </div>
</section>
<aside class="aside" aria-label="Detector notes">
  <section class="panel aside-panel">
    <div class="panel-body">
      <h2>What this measures</h2>
      <ul class="rules">
        <li>The chi-square test compares even/odd pixel-value pairs. LSB replacement tends to equalise each pair.</li>
        <li>A p-value above 0.05 means the low bit is as uniform as replacement would make it. This is a screening threshold, not proof.</li>
        <li>Noise fill alone does not guarantee a flag: LSB matching moves values by ±1 instead of overwriting their low bit.</li>
        <li>The header scan catches the old sequential <span class="mono">STEG1</span> format only.</li>
      </ul>
    </div>
  </section>
  <section class="panel aside-panel">
    <div class="panel-body">
      <h2>Honest reading</h2>
      <p class="aside-caption">A negative result from one detector is not proof of invisibility. The v2 format removes the magic bytes and sequential layout, but full-plane noise fill is a deliberate, measurable trade-off.</p>
    </div>
  </section>
</aside>
</div>"""


def _detection_card(label: str, report: dict) -> str:
    badge = '<span class="badge hit">Flagged</span>' if report["flagged"] else '<span class="badge clean">Not flagged</span>'
    return f"""<div class="report-card">
  <h3>{_esc(label)} {badge}</h3>
  <div class="specs">
    <div class="spec"><span>Chi-square</span><b>{report["chi_square"]:,}</b></div>
    <div class="spec"><span>Degrees of freedom</span><b>{report["dof"]}</b></div>
    <div class="spec"><span>p-value</span><b>{report["p_value"]}</b></div>
    <div class="spec"><span>χ² / df</span><b>{report["pair_ratio"]}</b></div>
    <div class="spec"><span>Legacy header</span><b>{"STEG1" if report["legacy_header"] else "none"}</b></div>
  </div>
  <p class="aside-caption">{_esc(report["verdict"])}</p>
</div>"""


@app.get("/detect", response_class=HTMLResponse)
def detect_page():
    if not features.load()["detection_enabled"]:
        return _disabled("Detector", "detect")
    return page("Detector", _detect_form(), active="detect")


@app.post("/detect", response_class=HTMLResponse)
async def do_detect(
    image: UploadFile = File(...),
    message: str = Form(""),
    password: str = Form(""),
):
    flags = features.load()
    if not flags["detection_enabled"]:
        return _disabled("Detector", "detect")
    try:
        raw = await _read_upload(image, flags["max_upload_mb"])
        before = analyze(raw)
        after = None
        stats = None
        if message.strip():
            if len(password) < 4:
                raise ValueError("password must be at least 4 characters to embed a test payload")
            stego, stats = encode(raw, message, password, noise=flags["noise_fill_enabled"])
            after = analyze(stego)
    except (StegError, ValueError) as exc:
        return page("Detector", _detect_form(str(exc)), 400, "detect")

    cards = _detection_card("Original image", before)
    if after is not None:
        cards += _detection_card("After embedding", after)
        cards += (
            f'<p class="form-note">Test payload: {stats["message_bytes"]:,} B in '
            f'{stats["payload_bytes"]:,} B of payload, {stats["fill_percent"]}% fill, '
            f'PSNR {stats["psnr_db"]} dB.</p>'
        )
    body = f"""<div class="page-head">
  <div><h1>Detection result</h1>
  <p class="lede">Measured on this upload. Verdicts describe statistical structure, not message recovery.</p></div>
  <span class="head-note">{"Before and after" if after else "Single image"}</span>
</div>
<div class="report-grid">{cards}</div>
<section class="explain" aria-labelledby="detect-reading">
  <div class="explain-head"><h2 id="detect-reading">How to read it</h2><span class="hint">One detector, stated limits</span></div>
  <div class="explain-grid">
    <div><h3>High p-value</h3><p>Above the 0.05 screening threshold the even/odd pairs are as uniform as replacement would make them. That is a signal, not a decryption.</p></div>
    <div><h3>Low p-value</h3><p>Below 0.05 this test did not flag the image. It does not rule out a payload hidden by another method.</p></div>
    <div><h3>What changed in v2</h3><p>The magic header is gone, positions are keyed, and LSB matching avoids the strong pair equalisation left by replacement.</p></div>
  </div>
</section>"""
    return page("Detector", body, active="detect")


@app.get("/download/{output_id}")
def download(output_id: str):
    if not _OUTPUT_ID.fullmatch(output_id):
        raise HTTPException(404)
    for ext, media_type in (("png", "image/png"), ("bmp", "image/bmp")):
        path = data_dir() / "outputs" / f"{output_id}.{ext}"
        if path.is_file():
            return FileResponse(path, media_type=media_type, filename=f"stego-{output_id}.{ext}")
    raise HTTPException(404)


@app.get("/research", response_class=HTMLResponse)
def research():
    flags = features.load()
    if not flags["research_enabled"]:
        return _disabled("Research dashboard", "research")
    rows = _history()[-25:]
    psnrs = [row["psnr_db"] for row in rows if isinstance(row.get("psnr_db"), (int, float))]
    fills = [row["fill_percent"] for row in rows if isinstance(row.get("fill_percent"), (int, float))]
    largest = max((row.get("message_bytes") for row in rows if isinstance(row.get("message_bytes"), int)), default=0)
    median_psnr = statistics.median(psnrs) if psnrs else None
    avg_fill = sum(fills) / len(fills) if fills else None

    metrics = flags["metrics_enabled"]
    metric_head = '<th class="num">PSNR</th>' if metrics else ""
    if rows:
        body_rows = ""
        for row in reversed(rows):
            metric_cell = (
                f'<td class="num" data-label="PSNR">{_num(row.get("psnr_db"), 1, " dB")}</td>'
                if metrics
                else ""
            )
            body_rows += (
                f'<tr><td class="time" data-label="Time">{_esc(row.get("time", "—"))}</td>'
                f'<td class="num" data-label="Message">{_num(row.get("message_bytes"), 0)} B</td>'
                f'<td class="num" data-label="Capacity used">{_num(row.get("fill_percent"), 2, "%")}</td>{metric_cell}</tr>'
            )
        table = f"""<div class="table-wrap"><table>
  <thead><tr><th>Time</th><th class="num">Message</th><th class="num">Capacity used</th>{metric_head}</tr></thead>
  <tbody>{body_rows}</tbody>
</table></div>"""
    else:
        table = '<div class="empty">No encodes recorded yet. <a href="/">Encode an image</a> to populate this table.</div>'

    chart = ""
    if rows:
        recent = rows[-12:]
        peak = max(
            (row["fill_percent"] for row in recent if isinstance(row.get("fill_percent"), (int, float))),
            default=0,
        ) or 1
        bars = ""
        for row in recent:
            fill = row.get("fill_percent")
            fill = fill if isinstance(fill, (int, float)) else 0
            width = max(2, round(100 * fill / peak, 1)) if fill else 0
            bars += (
                f'<div class="chart-row"><span class="chart-time">{_esc(str(row.get("time", "—"))[-8:])}</span>'
                f'<div class="chart-track"><div class="chart-fill" style="width:{width}%"></div></div>'
                f'<span class="chart-value">{_num(fill, 2, "%")}</span></div>'
            )
        chart = f'<div class="chart" role="img" aria-label="Capacity used by each of the last {len(recent)} encodes">{bars}</div>'
    else:
        chart = '<div class="empty">The chart fills in after the first encode.</div>'

    psnr_rows = [
        row
        for row in rows[-12:]
        if isinstance(row.get("psnr_db"), (int, float)) and isinstance(row.get("message_bytes"), int)
    ]
    if psnr_rows:
        peak_msg = max(row["message_bytes"] for row in psnr_rows) or 1
        bars = ""
        for row in psnr_rows:
            width = max(2, round(100 * row["message_bytes"] / peak_msg, 1))
            bars += (
                f'<div class="chart-row"><span class="chart-time">{_num(row["message_bytes"], 0, " B")}</span>'
                f'<div class="chart-track"><div class="chart-fill" style="width:{width}%"></div></div>'
                f'<span class="chart-value">{_num(row.get("psnr_db"), 1, " dB")}</span></div>'
            )
        psnr_chart = f'<div class="chart" role="img" aria-label="Measured PSNR for each of the last {len(psnr_rows)} message sizes">{bars}</div>'
    else:
        psnr_chart = '<div class="empty">PSNR appears after the first encode with metrics enabled.</div>'

    buckets = [("0–5%", 0, 5), ("5–20%", 5, 20), ("20–50%", 20, 50), ("50–100%", 50, 100.01)]
    detect_bars = ""
    for label, low, high in buckets:
        sample = [
            row
            for row in rows
            if isinstance(row.get("fill_percent"), (int, float))
            and low <= row["fill_percent"] < high
            and isinstance(row.get("detected"), bool)
        ]
        if not sample:
            continue
        hits = sum(1 for row in sample if row["detected"])
        rate = round(100 * hits / len(sample), 1)
        detect_bars += (
            f'<div class="chart-row"><span class="chart-time">{label}</span>'
            f'<div class="chart-track"><div class="chart-fill" style="width:{rate}%"></div></div>'
            f'<span class="chart-value">{hits}/{len(sample)}</span></div>'
        )
    detect_chart = (
        f'<div class="chart" role="img" aria-label="Share of encodes flagged by the chi-square detector in each fill bucket">{detect_bars}</div>'
        if detect_bars
        else '<div class="empty">No detector results yet. Encode an image with the detector enabled.</div>'
    )

    body = f"""<div class="page-head">
  <div><h1>Research</h1>
  <p class="lede">Every encode records its size and image-quality cost. This is the measured evidence, not a literature estimate.</p></div>
  <span class="head-note">Last 25 encodes</span>
</div>
<div class="kpi-row">
  {_kpi("Encodes shown", _num(len(rows)))}
  {_kpi("Median PSNR", _num(median_psnr, 1, " dB") if metrics else "—")}
  {_kpi("Average capacity used", _num(avg_fill, 1, "%"))}
  {_kpi("Largest message", _num(largest, 0, " B"))}
</div>
<div class="section-head"><h2>Recent encodes</h2><span class="hint">Most recent first</span></div>
{table}
<div class="research-grid">
  <section aria-labelledby="capacity-chart">
    <div class="section-head"><h2 id="capacity-chart">Capacity per encode</h2><span class="hint">Bars scaled to the largest shown</span></div>
    {chart}
  </section>
  <aside class="panel aside-panel" aria-label="Metric definitions">
    <div class="panel-body">
      <h2>Reading the numbers</h2>
      <div class="defs-stack">
        <div><h3>PSNR</h3><p>Peak signal-to-noise ratio between cover and stego, in dB. Values above roughly 40 dB are generally considered visually indistinguishable.</p></div>
        <div><h3>Capacity used</h3><p>Payload bytes including the 49-byte header and GCM tag, divided by the image's raw least-significant-bit capacity.</p></div>
        <div><h3>MSE</h3><p>Mean squared error per RGB channel. It is the input to PSNR, so a lower value means fewer pixel values moved.</p></div>
      </div>
    </div>
  </aside>
</div>
<div class="research-grid">
  <section aria-labelledby="psnr-chart">
    <div class="section-head"><h2 id="psnr-chart">PSNR by message size</h2><span class="hint">Bar length is message size; value is measured PSNR</span></div>
    {psnr_chart}
  </section>
  <aside class="panel aside-panel" aria-label="Detector results">
    <div class="panel-body">
      <h2>Detector hit rate by fill</h2>
      <p class="aside-caption">Real chi-square verdicts recorded during encode. Full-plane noise fill is expected to be flagged.</p>
      {detect_chart}
    </div>
  </aside>
</div>"""
    return page("Research", body, active="research")


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    if not _is_admin(request):
        return page("Admin login", _login_form(), active="admin")
    saved = '<div class="notice-ok" role="status">Feature flags saved.</div>' if request.query_params.get("saved") else ""
    return page("Admin", _admin_body(features.load(), saved), active="admin")


@app.post("/admin/login")
def admin_login(request: Request, password: str = Form(...)):
    if _blocked(request):
        return page(
            "Admin login",
            _login_form("Too many failed attempts. Try again in a minute."),
            429,
            "admin",
        )
    if not hmac.compare_digest(password, _admin_password()):
        _fail_login(request)
        return page("Admin login", _login_form("That password did not match."), 401, "admin")
    _clear_fails(request)
    response = RedirectResponse("/admin", status_code=303)
    response.set_cookie(COOKIE, _admin_cookie(), httponly=True, samesite="lax", max_age=8 * 3600)
    return response


@app.post("/admin/logout")
def admin_logout():
    response = RedirectResponse("/admin", status_code=303)
    response.delete_cookie(COOKIE)
    return response


@app.post("/admin/flags", response_class=HTMLResponse)
def save_flags(
    request: Request,
    encode_enabled: str | None = Form(None),
    decode_enabled: str | None = Form(None),
    metrics_enabled: str | None = Form(None),
    research_enabled: str | None = Form(None),
    detection_enabled: str | None = Form(None),
    diff_enabled: str | None = Form(None),
    noise_fill_enabled: str | None = Form(None),
    max_upload_mb: int = Form(...),
):
    if not _is_admin(request):
        return page("Forbidden", '<div class="page-head"><div><h1>403</h1><p class="lede">Log in first.</p></div></div>', 403, "admin")
    changes = {
        "encode_enabled": encode_enabled is not None,
        "decode_enabled": decode_enabled is not None,
        "metrics_enabled": metrics_enabled is not None,
        "research_enabled": research_enabled is not None,
        "detection_enabled": detection_enabled is not None,
        "diff_enabled": diff_enabled is not None,
        "noise_fill_enabled": noise_fill_enabled is not None,
        "max_upload_mb": max_upload_mb,
    }
    try:
        features.update(changes)
    except ValueError as exc:
        return page("Admin", _admin_body(features.load(), error=str(exc)), 400, "admin")
    return RedirectResponse("/admin?saved=1", status_code=303)


async def _read_upload(upload: UploadFile, limit_mb: int) -> bytes:
    limit = limit_mb * 1024 * 1024
    raw = await upload.read(limit + 1)
    if not raw:
        raise ValueError("please choose an image file")
    if len(raw) > limit:
        raise ValueError(f"file is larger than the {limit_mb} MB limit")
    return raw


def _record(stats: dict, detected: bool | None = None) -> None:
    try:
        path = data_dir() / "history.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "message_bytes": stats["message_bytes"],
            "payload_bytes": stats["payload_bytes"],
            "capacity_bytes": stats["capacity_bytes"],
            "fill_percent": stats["fill_percent"],
            "psnr_db": stats["psnr_db"],
            "detected": detected,
        }
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def _history() -> list[dict]:
    try:
        lines = (data_dir() / "history.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    rows = []
    for line in lines:
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows
