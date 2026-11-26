/* PhishShield UI：以文字節點呈現結果，分開標示執行狀態、分類與模擬模式。 */
'use strict';
const $ = id => document.getElementById(id);
const labels = {SAFE:'分析判定安全',SUSPICIOUS:'需留意的訊號',PHISHING:'釣魚風險',UNKNOWN:'交由人員判斷'};
const modelReasons={
  CORE_EVIDENCE_UNAVAILABLE:'必要原文證據無法取得，判斷未採用',LLM_SCHEMA_UNSUPPORTED:'AI 請求格式未通過檢查',
  LLM_TIMEOUT:'逾時',ANALYSIS_TIMEOUT:'分析逾時',LLM_CONNECTION_LOST:'連線中斷',
  LLM_RECONNECT_FAILED:'重連失敗',LLM_OUTPUT_INVALID:'輸出格式無效',
  LLM_EVIDENCE_INVALID:'證據引用無效',LLM_PROVIDER_FAILED:'模型服務失敗',LLM_AUTH_FAILED:'模型服務認證或權限未通過',
  LLM_RETRY_DELAY_LIMIT:'重試等待超限',LLM_NOT_CONFIGURED:'未設定模型',
  LLM_CONFIGURATION_INVALID:'模型設定無效',INVALID_LLM_INPUT:'模型輸入無效',
  LLM_INPUT_TOO_LARGE:'模型輸入超限',MODEL_NOT_STARTED:'未開始模型流程',
  EMPTY_INPUT:'無郵件內容',INVALID_INPUT_TYPE:'輸入格式無效',
  INVALID_TEXT_ENCODING:'文字編碼無效',UNSUPPORTED_FILE_TYPE:'檔案格式不支援',
  UNSUPPORTED_FILE_CONTENT:'檔案內容不支援',UNSUPPORTED_MAILBOX_FORMAT:'需拆成單封郵件',
  INPUT_READ_FAILED:'讀取檔案失敗',INPUT_TOO_LARGE:'檔案超限',
  MIME_PART_LIMIT_EXCEEDED:'郵件部件超限',MIME_DEPTH_LIMIT_EXCEEDED:'郵件巢狀超限',
  HEADER_LIMIT_EXCEEDED:'標頭超限',TEXT_LIMIT_EXCEEDED:'正文超限',
  URL_LIMIT_EXCEEDED:'網址數量超限',URL_EVIDENCE_LIMIT_EXCEEDED:'網址證據超限',
  ATTACHMENT_LIMIT_EXCEEDED:'附件數量超限',PARSE_TIMEOUT:'解析逾時',
  PARSE_FAILED:'郵件解析失敗',PARSER_UNAVAILABLE:'解析程序不可用',
  UNKNOWN_RULE_ID:'規則設定無效',DUPLICATE_RULE_ID:'規則設定重複',
  INVALID_RULE_INPUT:'規則輸入無效',RULE_EVALUATION_FAILED:'規則未完成',
  ANALYSIS_SERVICE_FAILED:'分析服務失敗'
};
const truncatedOutputCopy='模型輸出達長度上限，回覆未完成；這次未採用模型判斷，請先對照信件與既有證據。';
function isOutputTruncated(data){
  if(data.status!=='FAILED'||data.model_analysis?.activated===false||data.model_analysis?.completed===true)return false;
  if(data.errors!==undefined&&!Array.isArray(data.errors))return false;
  const errors=data.errors||[];
  const codes=errors.length?errors.map(item=>item?.code):data.model_analysis?.reason_codes;
  if(!Array.isArray(codes)||!codes.includes('LLM_OUTPUT_INVALID'))return false;
  const envelope=data.model_diagnostics;
  let diagnostic=envelope?.diagnostic;
  if(diagnostic==null&&Array.isArray(envelope?.calls)){
    const call=envelope.calls[envelope.calls.length-1];
    if(['a','b'].includes(envelope.failed_stage)&&call?.stage===envelope.failed_stage&&call.error_code==='LLM_OUTPUT_INVALID')diagnostic=call.diagnostic;
  }
  return diagnostic?.reason==='output_truncated'&&diagnostic.finish_reason==='length'&&
    (diagnostic.category==null||diagnostic.category==='output_truncated');
}
function analysisErrorText(data,code,fallback){
  return code==='LLM_OUTPUT_INVALID'&&isOutputTruncated(data)?truncatedOutputCopy:
    reasons[code]||modelReasons[code]||fallback;
}
function modelState(data){
  const info=data.model_analysis;
  const codes=Array.isArray(info?.reason_codes)?info.reason_codes:[];
  if(data.simulation===true||codes.includes('SIMULATED_ANALYSIS'))return {label:'離線模擬',reason:'沒有呼叫真實模型。'};
  if(!info||typeof info.activated!=='boolean'||typeof info.completed!=='boolean'||(info.completed&&!info.activated))return {label:'未記錄',reason:'此筆紀錄未保存完整、可判讀的模型狀態。'};
  if(info.completed)return {label:'已完成',reason:'AI 已完成分析，回覆與引用原文已通過系統核對。'};
  const truncated=isOutputTruncated(data);
  const reason=(!info.activated&&info.skipped_by_rules===true)?'依規則政策跳過':truncated?'輸出達長度上限':codes.map(code=>modelReasons[code]).find(Boolean)||'原因未記錄';
  return {label:(info.activated?'未完成':'未啟用')+' · '+reason,reason:info.activated?(truncated?truncatedOutputCopy:'AI 已開始分析，但尚未取得可採用的完整回覆。'):'模型流程沒有啟動。'};
}
function modelLabel(data){return modelState(data).label;}
function renderModelAnalysis(data){
  const block=section('模型分析');
  const info=data.model_analysis;
  block.append(element('p',modelLabel(data),'badge'),element('p',modelState(data).reason,'note'));
  if(!info)return;

  for(const text of [...new Set((info.reason_codes||[]).map(code=>code==='LLM_OUTPUT_INVALID'&&isOutputTruncated(data)?truncatedOutputCopy:reasons[code]).filter(Boolean))])block.append(element('p',text,'note'));
  if(info.rules_matched)block.append(element('p',info.skipped_by_rules?'本次採用既有檢查結果，未送交 AI 分析。':'文字檢查發現需留意的內容，本次也已啟動 AI 分析。','note'));
}
const reasons = {UNKNOWN:'需交由人員判斷，目前資訊不足以判定風險。',MODEL_ANALYSIS_COMPLETED:'模型分析已完成並通過輸出驗證。',MODEL_NOT_STARTED:'尚未開始模型分析。',SIMULATED_ANALYSIS:'此為離線模擬，不構成真實郵件判斷。',EVIDENCE_INSUFFICIENT:'證據或資訊不足。',REVIEW_REQUIRED:'以下項目需交由人員判斷。',MODEL_RECOMMENDATION:'採用經驗證的模型建議。',TRUSTED_MALICIOUS_URL:'命中已驗證且有效的可信網址情報。',LLM_NOT_CONFIGURED:'尚未設定 AI 服務，請完成環境變數設定並重新啟動後台。',LLM_TIMEOUT:'模型分析逾時，未成功完成。',LLM_ENDPOINTS_OFFLINE:'AI 服務離線，此階段的端點已全部嘗試且無法使用。請稍後重新檢查連線。',LLM_TEST_MODE_DISABLED:'離線模擬僅供測試工具，請配置可用 AI。',LLM_CONNECTION_LOST:'模型連線中斷，重試後仍未完成。',LLM_RECONNECT_FAILED:'無法清理或重建連線，分析已停止。',LLM_OUTPUT_INVALID:'模型輸出格式無效，結果未採用。',LLM_EVIDENCE_INVALID:'AI 引用的原文未通過核對，這次未採用完整模型結論。請對照原文或重新分析。',EMPTY_INPUT:'沒有可分析的內容。',MODEL_REASON_REDACTED:'模型另有分析理由；自由文字未保存。'};
let inputMode='file';
let busy=false,page=1,pageSize=10,total=0,sourceMode='new',historySequence=0;
let currentReport=null, exportBusy=false;
let busyClockTimer,busyStartedAt=0,busyClockScope='',analysisPreviewReady=false;
const selectedReports=new Set();
const historyCheckboxes=new Map();
let historyItems=[], historyFilters={};
function element(tag,text,cls){const node=document.createElement(tag);if(text!==undefined)node.textContent=String(text);if(cls)node.className=cls;return node;}
function loadingState(message){
  const node=element('div',undefined,'loading-state');
  node.append(element('p',message));
  for(let i=0;i<3;i++){const bar=element('span',undefined,'skeleton');bar.setAttribute('aria-hidden','true');node.append(bar);}
  return node;
}
function clearResultDetails(){currentReport=null;$('export-status').textContent='';updateExportControls();$('result-details').replaceChildren(element('p','尚未取得詳細結果；請先完成分析。','note'));}
function stopBusyClock(){
  clearTimeout(busyClockTimer);busyClockTimer=undefined;busyClockScope='';
  $('activity-elapsed').hidden=true;$('activity-elapsed').textContent='';
}
function updateBusyClock(){
  if(!busy||!busyClockScope)return;
  const elapsed=Math.max(0,Math.floor((Date.now()-busyStartedAt)/1000));
  $('activity-elapsed').textContent=(busyClockScope==='batch'?'本批已等待 ':'已等待 ')+elapsed+' 秒';
  $('activity-detail').textContent=elapsed>=30?'尚未收到完整分析結果，請保留目前頁面，避免重複提交。':
    busyClockScope==='batch'?'正在等候目前這封信的完整結果，其餘檔案將依序送出。':
    analysisPreviewReady?'初步文字檢查已完成，正在等候完整分析結果。':'完整分析等待中，尚未取得最終判斷。';
}
function startBusyClock(){
  analysisPreviewReady=false;
  if(sourceMode==='history'){$('activity-detail').textContent='正在讀取已保存的紀錄。';return;}
  busyStartedAt=Date.now();busyClockScope=batchRunning?'batch':'analysis';
  $('activity-elapsed').hidden=false;updateBusyClock();
  const tick=()=>{if(!busy||!busyClockScope)return;updateBusyClock();busyClockTimer=setTimeout(tick,1000);};
  busyClockTimer=setTimeout(tick,1000);
}
function setBusy(value,message=''){
  stopBusyClock();busy=value;
  if(value)$('activity-label').textContent=message||'處理中，請稍候';
  $('analysis-activity').hidden=!value;$('analyze-view').classList.toggle('is-processing',value);
  if(value)clearResultDetails();
  for(const id of ['email-file','email-text','input-tab-file','input-tab-text','clear-file','check-model','tab-history'])$(id).disabled=value||(sourceMode==='history'&&['email-file','email-text','input-tab-file','input-tab-text','clear-file'].includes(id))||(id==='check-model'&&modelCheckRunning)||(id==='email-text'&&inputMode!=='text')||(id==='email-file'&&inputMode!=='file');
  $('result').setAttribute('aria-busy',String(value));$('result-details').setAttribute('aria-busy',String(value));
  $('new-analysis').hidden=sourceMode!=='history';$('new-analysis').disabled=value;
  $('submit-analysis').disabled=value||sourceMode==='history';$('submit-analysis').hidden=sourceMode==='history';
  $('submit-label').textContent=value?'處理中…':sourceMode==='history'?'歷史紀錄檢視中':'開始分析';
  $('submit-analysis').setAttribute('aria-busy',String(value));$('form-status').className='form-status';$('form-status').textContent=message;
  if(value)startBusyClock();
}
function showTab(name){
  for(const tab of ['analyze','history']){
    $(tab+'-view').hidden=tab!==name;
    $('tab-'+tab).classList.toggle('active',tab===name);
    $('tab-'+tab).setAttribute('aria-current',tab===name?'page':'false');
  }
  const heading={analyze:['郵件分析筆記','匯入信件，對照原文與分析證據。'],history:['查看分析紀錄','找到信件，重看結果或下載報告。']}[name];
  $('workspace-title').textContent=heading[0];$('workspace-intro').textContent=heading[1];
}

function syncInputMode(){
  for(const mode of ['file','text']){
    const selected=mode===inputMode;
    $('input-panel-'+mode).hidden=!selected;
    $('input-tab-'+mode).setAttribute('aria-selected',String(selected));
    $('input-tab-'+mode).setAttribute('tabindex',selected?'0':'-1');
  }
}
function selectInputMode(mode,focus=false){
  if(busy||sourceMode==='history'||!['file','text'].includes(mode))return;
  if(inputMode!==mode){inputMode=mode;syncInputMode();setBusy(false);inputChanged();clearTimeout(previewTimer);refreshInputPreview();}
  if(focus)$('input-tab-'+mode).focus();
}
for(const mode of ['file','text']){
  $('input-tab-'+mode).addEventListener('click',()=>selectInputMode(mode));
  $('input-tab-'+mode).addEventListener('keydown',event=>{
    if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;
    event.preventDefault();selectInputMode(event.key==='Home'?'file':event.key==='End'?'text':mode==='file'?'text':'file',true);
  });
}

const readingTabs=['mail','result'];
function showReadingTab(name,focus=false){
  for(const tab of readingTabs){
    const selected=tab===name;
    $('reading-panel-'+tab).hidden=!selected;
    $('reading-tab-'+tab).setAttribute('aria-selected',String(selected));
    $('reading-tab-'+tab).setAttribute('tabindex',selected?'0':'-1');
  }
  if(focus)$('reading-tab-'+name).focus();
}
for(const [index,name] of readingTabs.entries()){
  $('reading-tab-'+name).addEventListener('click',()=>showReadingTab(name));
  $('reading-tab-'+name).addEventListener('keydown',event=>{
    let next;
    if(event.key==='ArrowRight')next=(index+1)%readingTabs.length;
    else if(event.key==='ArrowLeft')next=(index+readingTabs.length-1)%readingTabs.length;
    else if(event.key==='Home')next=0;
    else if(event.key==='End')next=readingTabs.length-1;
    else return;
    event.preventDefault();showReadingTab(readingTabs[next],true);
  });
}
async function request(path,options={}){const controller=new AbortController();const waitLimit=options.method==='POST'&&/^\/api\/v1\/analyses(?:\/file)?$/.test(path)?310000:65000;const timer=setTimeout(()=>controller.abort(),waitLimit);try{const response=await fetch(path,{...options,signal:controller.signal,cache:'no-store'});let data;try{data=await response.json();}catch(error){if(error.name==='AbortError'||controller.signal.aborted)throw error;throw new Error('服務回覆無效，請確認服務狀態。');}if(!response.ok&&!data.analysis_id)throw new Error(reasons[data.error_code]||'請求未成功完成，請確認輸入、資料庫及服務狀態。');return data;}catch(error){if(error.name==='AbortError'||controller.signal.aborted)throw new Error('連線等待逾時，未取得結果；請先查看分析紀錄，避免重複提交。');throw error;}finally{clearTimeout(timer);}}
function section(title){const block=element('section',undefined,'result-section');block.append(element('h4',title));$('result').append(block);return block;}
function renderPreview(data){if(data.source_document)renderMail(data.source_document);if(!data.preliminary)return;analysisPreviewReady=data.status!=='FAILED';updateBusyClock();const root=$('result');root.replaceChildren(element('div','完整分析等待中；初步文字檢查結果如下。','simulation'));for(const item of data.findings||[]){root.append(element('div',(item.category==='prompt_injection'?'注入訊號：':'命中可疑釣魚特徵：')+item.summary,'finding'));}if(!data.findings?.length)root.append(element('p',analysisPreviewReady?'文字檢查已完成，正在等待完整分析結果。':'初步解析未完成，正在等待完整分析回覆。','note'));}
function renderSourceDocument(data){
  const block=section('信件內容｜人工判讀');
  const doc=data.source_document;
  if(!doc){block.append(element('p','此筆舊紀錄未保存原始內容，無法還原；請重新上傳原始信件。','note'));return;}
  const storage=data.persistence?.state;
  const storageNote=storage==='not_saved'?'本次結果尚未保存，請保留原始信件。':storage==='unconfirmed'?'尚未確認保存結果，請先以分析識別查詢歷史，避免重複提交。':'內容已保存在本機歷史紀錄。';
  block.append(element('p',storageNote+'信件 HTML、腳本及網址皆只作文字顯示。','note'));
  const pasted=doc.source==='pasted_text';
  if(pasted)block.append(element('h4','原始貼上本文／TXT 原文'),element('pre',doc.raw_text||'（空白內容）','source-text'));
  const mail=doc.parsed;
  if(mail){
    const metadata=element('div',undefined,'source-metadata');
    for(const [name,value] of [['主旨',mail.subject],['寄件者',mail.sender],['回覆地址',mail.reply_to],['收件者',(mail.recipients||[]).join('、')]])metadata.append(element('p',name+'：'+(value||'（未提供）')));
    block.append(metadata,element('h4',pasted?'整理後的信件正文':'解碼正文'),element('pre',mail.body_text||'（無可顯示正文）','source-text'));
  }else block.append(element('p',pasted?'解析未成功；原始本文仍顯示於上方。':'解析未成功，請參考下方原始檔文字。','note'));
  if(!pasted){
  const details=element('details');
  details.append(element('summary','展開原始檔文字（含標頭／MIME）'),element('p',doc.raw_text_note,'note'),element('pre',doc.raw_text||'（空白檔案）','source-text'));
  block.append(details);
  }
}
const categoryTitles={authentication:'寄件者是否可信',urgency_fear:'是否催促或威脅',generic_salutation:'如何稱呼收件人',url_structure:'連結導向何處',language:'用字與語氣',credential_request:'敏感資料要求',impersonation:'身分冒用跡象',url_deception:'網址偽裝跡象',analysis_override:'干預分析的文字',risky_attachment:'高風險附件副檔名',account_access:'帳戶登入或驗證要求',secret_disclosure:'秘密資料要求',software_execution:'軟體執行或安裝要求',payment_request:'付款或轉帳要求',coercive_request:'期限與聲稱後果',linked_execution:'下載與執行的關係',program_signal:'獨立文字或網址模式',event_fact:'模型提取的表述'};
const reviewGuidance={
  URL_BOUNDARY_AMBIGUOUS:['連結範圍需要確認','信中文字與網址連在一起，可能影響連結擷取。','請從原始信件確認完整網址，並向寄件單位核實。'],
  URL_PARSE_WARNING:['連結無法完整辨識','部分網址格式無法可靠讀取。','請對照原始信件中的連結，不要直接開啟。'],
  INTERNATIONALIZED_DOMAIN:['核對網域字形','連結使用國際化網域，字形可能與熟悉的網址相似。','請逐字核對正式網域，或從已知的官方入口進入。'],
  MISSING_SENDER:['缺少寄件者資訊','這份內容沒有提供寄件地址。','可補上完整 EML，或透過既有聯絡方式確認寄件人。'],
  MISSING_SUBJECT:['缺少信件主旨','這份內容沒有提供主旨。','請對照完整信件，確認其與內文及預期業務相符。'],
  MULTIPLE_SENDERS:['寄件身分需要確認','信件標頭列出多個寄件者。','請向郵件管理人員確認實際寄件來源。'],
  UNTRUSTED_AUTH_HEADERS:['寄件驗證尚未確認','信內的驗證欄位尚未由可信郵件服務核實。','請向郵件管理人員查核 SPF、DKIM、DMARC 結果。'],
  EMPTY_BODY:['沒有可讀取的正文','目前沒有取得可供分析的信件正文。','請確認檔案內容，或重新匯入完整 EML。'],
  UNSUPPORTED_INLINE_CONTENT:['有內容尚未檢查','信件包含目前無法分析的內嵌內容。','請在受控環境中交由資訊人員檢查。'],
  HIDDEN_CONTENT_PRESENT:['另有隱藏文字','信件內含可能未顯示於一般閱讀畫面的文字。','請對照原文與解碼正文，確認是否影響信件意思。'],
  HTML_VISIBILITY_APPROXIMATE:['顯示內容可能不同','靜態文字預覽可能與郵件軟體的畫面不同。','請對照完整正文及原始信件，確認重要內容。']
};
function uniqueText(values){return [...new Set(values.filter(value=>typeof value==='string'&&value.trim()).map(value=>value.trim()))];}
function nextStep(text){
  if(/網址|連結|URL|網站/i.test(text))return '建議從已知的官方入口查證，先不要點擊信內連結。';
  if(/寄件|身分|身份|SPF|DKIM|DMARC/i.test(text))return '建議透過既有聯絡方式確認寄件人，必要時請郵件管理人員協助。';
  return '建議向熟悉這項業務的聯絡人確認，使用既有的電話或通訊管道。';
}
function readerNotes(data){
  const model=data.analysis_explanation?.available&&!isOutputTruncated(data)?data.analysis_explanation.model:null;
  const notes=uniqueText([...(model?.uncertainties||[]),...(model?.scope_limitations||[]),...(model?.explanations||[]).filter(item=>item.assessment==='not_verified').map(item=>item.explanation)]).map(text=>({title:'仍待確認',detail:text,action:nextStep(text),refs:[]}));
  const seen=new Set();
  const reviews=[...(data.review_items||[]),...(data.analysis_explanation?.review_items||[])];
  for(const item of reviews){
    const code=item.code||'';
    if(['REVIEW_REQUIRED','LLM_UNCERTAINTY','SIMULATED_ANALYSIS'].includes(code)||seen.has(code))continue;
    seen.add(code);
    let copy=reviewGuidance[code];
    if(!copy&&/CHARSET|DECODE|MIME|HEADER/.test(code))copy=['文字可能不完整','信件的編碼或格式有異常，部分內容可能無法正確讀取。','請對照原始信件，若有亂碼或缺漏，重新匯入完整 EML。'];
    if(!copy&&/UNICODE|MIXED_SCRIPT/.test(code))copy=['核對文字字形','信件含特殊字元或混用字形，可能影響閱讀。','請對照原文，特別確認寄件地址、品牌名稱與網址。'];
    if(copy&&!notes.some(note=>note.detail===copy[1]))notes.push({title:copy[0],detail:copy[1],action:copy[2],refs:item.evidence_refs||[]});
  }
  if(!notes.length&&reviews.some(item=>!['SIMULATED_ANALYSIS'].includes(item.code)))notes.push({title:'需要補充背景',detail:'現有信件資訊仍有需要人員確認之處。',action:'請對照完整信件，向既有業務聯絡人確認內容及要求是否符合預期。',refs:[]});
  return notes;
}
function appendEvidence(block,refs,data){
  const sources=[...(!isOutputTruncated(data)?data.analysis_explanation?.model?.evidence||[]:[]),...(data.source_document?.evidence||[])];
  for(const ref of refs||[]){
    const source=sources.find(item=>item.ref===ref);
    const node=disclosure('引用原文',element('pre',evidenceText(source?.text??'此筆紀錄未保存這段原文，請對照完整信件。'),'source-text'),element('small','原文位置 '+ref,'note'));
    block.append(node);
  }
}
function renderExplanation(data){
  const block=section('分析理由與證據');
  const report=data.analysis_explanation;
  const model=report?.available&&!isOutputTruncated(data)?report.model:null;
  if(!model){block.append(element('p',isOutputTruncated(data)?truncatedOutputCopy:data.simulation?'這次為操作流程模擬。切換至 AI 分析後，可取得信件判斷理由。':'目前沒有可採用的完整 AI 判斷理由。請參考已發現的內容及下方確認事項。','note'));return;}
  block.append(element('p',model.source_note||'此筆舊紀錄未記錄理由來源，請對照原文。','note'));
  if(report.presentation?.status==='degraded')block.append(element('p','核心判斷已完成；詳細說明暫時無法整理，請對照所附原文。','note'));
  if(data.coverage?.status==='incomplete')block.append(element('p','本次僅涵蓋部分可分析內容，不能用來認定整封信件安全。請對照完整原文。','note'));
  if(model.rationale)block.append(element('p',model.rationale,'rationale'));
  const shown=new Set();
  for(const reason of model.explanations||[]){
    if(reason.assessment==='not_verified'||shown.has(reason.explanation))continue;
    shown.add(reason.explanation);
    const card=element('div',undefined,'finding');
    card.append(element('h4',categoryTitles[reason.category]||'信件內容觀察'),element('p',reason.explanation));
    appendEvidence(card,reason.evidence_refs,data);block.append(card);
  }
  for(const feature of model.features||[]){
    if(shown.has(feature.description))continue;
    shown.add(feature.description);
    const item=element('div',feature.description,'finding');
    appendEvidence(item,feature.evidence_refs,data);block.append(item);
  }
  if(!(model.explanations?.length||model.features?.length))appendEvidence(block,model.evidence_refs,data);
  for(const text of uniqueText(model.social_engineering_indicators||[]))block.append(element('p',text,'note'));
}
function renderRuleSignals(data){
  if(!data.rule_findings?.length)return;
  const block=section('信件中值得注意的內容');
  for(const finding of data.rule_findings){const node=element('div',finding.summary,'finding');appendEvidence(node,finding.evidence_refs,data);block.append(node);}
}
function threatCount(data){return data.rule_signal_summary?.email_threat_count??(data.rule_findings||[]).filter(item=>item.category==='email_threat').length;}
function riskHeading(data,classification){return classification==='UNKNOWN'&&threatCount(data)>0?'已偵測可疑釣魚特徵':labels[classification];}
function renderFullResult(data){
  const root=$('result');root.replaceChildren();
  const classification=data.status==='FAILED'?'UNKNOWN':data.final_classification;
  if(!Object.hasOwn(labels,classification))throw new Error('分析結果無效，沒有可用的分類。');
  const box=element('div',undefined,'classification');
  if(classification==='SAFE')box.classList.add('safe');
  if(classification==='PHISHING')box.classList.add('phishing');
  box.append(element('span',modelLabel(data),'badge'),element('h3',riskHeading(data,classification)),element('p',classification==='UNKNOWN'?(threatCount(data)>0?'信件已有可疑內容，整體風險交由人員判斷。':'目前資訊不足以形成安全或釣魚結論。'):'請搭配信件情境與下方證據閱讀。'));
  root.append(box);
  renderExplanation(data);renderRuleSignals(data);
  const notes=readerNotes(data);
  if(notes.length){
    const block=section('建議確認事項');
    for(const note of notes){const item=element('div',undefined,'review-note');item.append(element('h4',note.title),element('p',note.detail),element('p',note.action,'next-action'));appendEvidence(item,note.refs,data);block.append(item);}
  }
  renderSourceDocument(data);
  if(data.evidence?.length){const block=section('證據定位');for(const item of data.evidence)appendEvidence(block,[item.ref],data);}
  renderModelAnalysis(data);
  const completion=section('分析執行情況');
  completion.append(element('p',data.status==='FAILED'?'分析未完成，已取得的內容保留供判讀。':classification==='UNKNOWN'?'分析流程已完成，但現有證據不足以判定風險。':'分析流程已完成。','note'));
  if(data.status==='FAILED'){
    completion.append(element('p','中止於'+({1:'信件讀取',2:'文字檢查',3:'AI 分析',4:'結果整理'}[data.failed_phase]||'分析流程'),'note'));
    for(const error of data.errors||[])completion.append(element('p',analysisErrorText(data,error.code,'分析服務未能完成本次處理，請確認服務後重試。'),'error-message'));
  }
}
function disclosure(title,...children){const node=element('details',undefined,'disclosure');node.append(element('summary',title),...children);return node;}
function evidenceText(text){
  try{const value=JSON.parse(text);if(value&&typeof value==='object'&&('href' in value||'normalized_url' in value))return ['網址：'+(value.href||value.normalized_url||'（無）'),'實際主機：'+(value.hostname||'（無法解析）'),value.display_text?'顯示文字：'+value.display_text:''].filter(Boolean).join('\n');}catch{}
  return text;
}
function renderMail(doc){
  const root=$('mail-preview');root.replaceChildren();
  if(!doc){root.append(element('p','此筆紀錄未保存信件內容，請重新匯入。','note'));return;}
  const mail=doc.parsed;
  root.append(element('span',doc.source==='eml_upload'?'EML 郵件':'文字／TXT','source-label'));
  root.append(element('h3',mail?.subject||'郵件內容','mail-subject'));
  if(mail?.sender||mail?.recipients?.length){
    const meta=element('div',undefined,'mail-addresses');
    if(mail.sender)meta.append(element('p','寄件者　'+mail.sender));
    if(mail.recipients?.length)meta.append(element('p','收件者　'+mail.recipients.join('、')));
    if(mail.reply_to)meta.append(element('p','回覆至　'+mail.reply_to));
    root.append(meta);
  }
  root.append(element('pre',doc.display_body_text??mail?.body_text??doc.raw_text??'（空白內容）','mail-body'));
  root.append(disclosure('查看原始文字',element('pre',doc.raw_text||'（空白內容）','source-text'),element('p',doc.raw_text_note||'原始提交內容；網址與標記只作文字顯示。','note')));
  $('preview-status').textContent='僅顯示文字，不執行信件腳本或載入外部圖片。';
}
function renderResult(data){
  renderFullResult(data);
  const root=$('result');
  const full=Array.from(root.children);
  const hero=full.find(node=>node.className.split(' ').includes('classification'));
  const details=full.filter(node=>node!==hero&&node.className!=='simulation'&&node.className!=='result-meta');
  // Build a compact view; the complete report remains available on demand.
  root.replaceChildren();
  if(data.simulation)root.append(element('p','離線模擬 · 不構成真實郵件判斷','simulation'));
  hero.replaceChildren(...Array.from(hero.children).slice(1));
  root.append(hero);
  const status=element('div',undefined,'result-meta');
  status.append(element('span','模型分析：'+modelLabel(data),'badge'),element('span',data.status==='FAILED'?'整體分析未完成':'分析流程已完成','badge'));
  if(data.analysis_explanation?.presentation?.status==='degraded')status.append(element('span','說明簡略 · 核心判斷已保留','badge'));
  if(data.coverage?.status==='incomplete')status.append(element('span','部分內容未涵蓋，請對照完整原文','badge'));
  const semantic=data.analysis_reliability?.semantic_extraction;
  if(semantic?.availability==='recorded'&&semantic.semantic_completeness!=='complete')status.append(element('span','行為提取仍需核對','badge'));
  root.append(status);
  const model=data.analysis_explanation?.available&&!isOutputTruncated(data)?data.analysis_explanation.model:null;
  const summary=section('判斷摘要');
  summary.append(element('p',isOutputTruncated(data)?truncatedOutputCopy:model?.rationale||(data.status==='FAILED'?(data.rule_findings?.length?'已發現值得留意的信件內容，完整 AI 判斷尚未完成。請先對照證據，再向寄件單位確認。':'目前沒有可採用的完整 AI 判斷。請對照原文並確認信件來源，或稍後重新分析。'):data.simulation?'這筆歷史紀錄來自測試模擬，不能作為真實風險判斷。':'目前資訊不足，請依原文與證據交由人員判斷。'),'rationale'));
  const observations=(model?.explanations||[]).filter(item=>item.assessment==='observed');
  const entries=observations.length?observations:(model?.features?.length?model.features:(data.rule_findings||[]));
  const signals=entries.length?section('重點觀察'):null;
  const titles=categoryTitles;
  for(const item of entries.slice(0,3)){
    const card=element('div',undefined,'signal-card');
    const content=element('div');content.append(element('h4',titles[item.category]||'風險訊號'),element('p',item.explanation||item.description||item.summary));
    card.append(content);signals.append(card);
  }
  const notes=readerNotes(data);
  if(notes.length){const block=section('建議確認事項');for(const note of notes.slice(0,2)){block.append(element('p',note.detail,'note'),element('p',note.action,'next-action'));}if(notes.length>2)block.append(element('p','另有 '+(notes.length-2)+' 項確認事項，請查看詳細結果。','note'));}
  if(data.status==='FAILED'){const block=section('分析未完成');for(const error of data.errors||[])block.append(element('p',analysisErrorText(data,error.code,'服務未能完成分析，請確認連線後重試。'),'error-message'));}
  renderReportDetails(details);
  currentReport=data;updateExportControls();
  const more=element('button','查看詳細結果 →','secondary');
  more.setAttribute('type','button');
  more.addEventListener('click',()=>showReadingTab('result',true));
  root.append(more);
  renderMail(data.source_document);
}
const batchLimits={files:20,fileBytes:2000000,totalBytes:20000000};
let batchItems=[],batchSelected=0,batchStop=false,batchRunning=false,batchInvalid='';
const batchLabels={pending:'待分析',processing:'分析中',completed:'已完成',failed:'未完成',rejected:'不接受',stopped:'未執行'};
function selectedFile(){if(inputMode!=='file')return null;return batchItems.length>1?batchItems[batchSelected]?.file:$('email-file').files[0];}
function renderBatch(){
  updateExportControls();
  $('batch-area').hidden=batchItems.length<2;
  $('batch-list').replaceChildren();
  const done=batchItems.filter(item=>!['pending','processing'].includes(item.state)).length;
  $('batch-progress').max=Math.max(batchItems.length,1);$('batch-progress').value=done;
  $('batch-status').textContent=batchInvalid||('已處理 '+done+' / '+batchItems.length+' 封'+(batchRunning?' · 逐封分析中':''));
  $('batch-stop').hidden=!batchRunning;$('batch-stop').disabled=batchStop;
  for(const [index,item] of batchItems.entries()){
    const button=element('button',undefined,'batch-item');
    button.setAttribute('type','button');button.setAttribute('aria-pressed',String(index===batchSelected));
    button.append(element('span',(index+1)+'. '+item.file.name,'batch-name'),element('small',batchLabels[item.state]+(item.result?' · '+(item.result.final_classification==='UNKNOWN'?'交由人員判斷':item.result.final_classification):'')+(item.error?' · '+item.error:'')));
    button.addEventListener('click',()=>viewBatch(index));
    $('batch-list').append(button);
  }
}
function prepareBatch(){
  const files=Array.from($('email-file').files);
  batchItems=files.length>1?files.slice(0,batchLimits.files).map(file=>({file,state:!/[.](eml|txt)$/i.test(file.name)?'rejected':file.size>batchLimits.fileBytes?'rejected':'pending',error:!/[.](eml|txt)$/i.test(file.name)?'批次僅接受 EML 或 UTF-8 TXT':file.size>batchLimits.fileBytes?'檔案超過 2 MB':'',result:null})):[];
  batchSelected=0;batchStop=false;
  batchInvalid=files.length>batchLimits.files?'每批最多 20 封，請重新選擇。':files.reduce((sum,file)=>sum+file.size,0)>batchLimits.totalBytes?'合計超過 20 MB，請分批選擇。':'';
  if(batchInvalid)batchItems.forEach(item=>{item.state='rejected';item.error=batchInvalid;});
  renderBatch();
}
async function viewBatch(index){
  batchSelected=index;previewSequence++;clearTimeout(previewTimer);renderBatch();showReadingTab('mail');
  const item=batchItems[index];
  if(item.result){renderResult(item.result);return;}
  clearResultDetails();
  $('result').replaceChildren(element('p',item.error||'這封信尚無分析結果。','note'));
  if(item.state==='rejected'){$('mail-preview').replaceChildren(element('p',item.error,'error-message'));return;}
  await refreshInputPreview();
}
async function analyzeBatch(mode){
  if(batchInvalid){$('form-status').textContent=batchInvalid;return;}
  if(!batchItems.some(item=>item.state==='pending')){$('form-status').textContent='沒有待分析的檔案；已完成或停止的批次不會自動重送，請重新選檔。';return;}
  batchStop=false;batchRunning=true;setBusy(true,'批次分析中，模式已固定。');renderBatch();showReadingTab('mail');
  try{
    for(const [index,item] of batchItems.entries()){
      if(item.state!=='pending')continue;
      if(batchStop)break;
      item.state='processing';renderBatch();
      $('form-status').textContent='正在分析第 '+(index+1)+' / '+batchItems.length+' 封：'+item.file.name;
      if(batchSelected===index){clearResultDetails();$('result').replaceChildren(loadingState('這封信正在分析中…'));}
      try{
        const form=new FormData();form.append('file',item.file);form.append('mode',mode);
        const result=await request('/api/v1/analyses/file',{method:'POST',body:form});
        if(!result.analysis_id)throw new Error('未取得有效結果，請先檢查歷史紀錄。');
        item.result=result;item.state=result.status==='FAILED'?'failed':'completed';
        item.error=result.persistence?.state==='unconfirmed'?'尚未確認保存，請先查看分析紀錄。':result.persistence?.state==='not_saved'?'本次結果未保存，請保留原始檔。':result.status==='FAILED'?analysisErrorText(result,result.errors?.[0]?.code,'分析未完成，請查看結果。'):'';
        if(batchSelected===index){previewSequence++;renderResult(result);}
      }catch(error){
        item.state='failed';item.error=error.message+' 請先查看歷史，避免重複提交。';
        if(batchSelected===index){previewSequence++;clearResultDetails();$('result').replaceChildren(element('p',item.error,'error-message'));}
      }
      renderBatch();
    }
  }finally{
    for(const item of batchItems)if(item.state==='pending'){item.state='stopped';item.error='停止前未送出，未建立分析紀錄';}
    batchRunning=false;renderBatch();
    const successful=batchItems.filter(item=>item.state==='completed').length;
    const failed=batchItems.filter(item=>['failed','rejected'].includes(item.state)).length;
    const stopped=batchItems.filter(item=>item.state==='stopped').length;
    setBusy(false,'批次結束：完成 '+successful+'、未完成／不接受 '+failed+'、未執行 '+stopped+'。可點選清單查看各封結果。');
  }
}
function clearInputSources(){
  $('email-file').value='';$('email-text').value='';$('clear-file').hidden=true;
  batchItems=[];batchSelected=0;batchStop=false;batchInvalid='';renderBatch();
  previewSequence++;previewCache=null;clearTimeout(previewTimer);
}
$('new-analysis').addEventListener('click',()=>{
  if(busy)return;
  sourceMode='new';clearInputSources();showTab('analyze');showReadingTab('mail');
  clearResultDetails();
  $('mail-preview').replaceChildren(element('p','請匯入要分析的信件或貼上本文。','note'));
  $('preview-status').textContent='尚未匯入信件';
  $('result').replaceChildren(element('p','等待新的信件；歷史紀錄仍可由分析紀錄查看。','note'));
  setBusy(false,'請選擇檔案或貼上新的郵件內容。');$(inputMode==='file'?'email-file':'email-text').focus();
});
$('batch-stop').addEventListener('click',()=>{batchStop=true;renderBatch();$('form-status').textContent='已要求停止；目前這封會完成，其餘不再送出。';});
let previewSequence=0,previewTimer,previewCache=null;
async function refreshInputPreview(){
  if(sourceMode==='history')return;
  const sequence=++previewSequence;
  const file=selectedFile(),text=inputMode==='text'?$('email-text').value:'';
  if(!file&&!text.trim()){$('mail-preview').replaceChildren(element('p','貼上內容或選擇檔案，即可查看。','note'));$('preview-status').textContent='尚未匯入信件';return;}
  if(inputMode==='file'&&batchItems.length>1&&batchItems[batchSelected]?.state==='rejected'){$('preview-status').textContent=batchItems[batchSelected].error;$('mail-preview').replaceChildren();return;}
  if(inputMode==='file'&&batchInvalid){$('preview-status').textContent=batchInvalid;$('mail-preview').replaceChildren();return;}
  if(file&&(file.size>2000000||!/[.](eml|txt)$/i.test(file.name))){$('preview-status').textContent='請選擇 2 MB 以內的 EML 或 TXT 檔案。';$('mail-preview').replaceChildren();return;}
  if(!file)renderMail({source:'pasted_text',raw_text:text,parsed:null});
  else $('mail-preview').replaceChildren(loadingState('正在解析信件…'));
  $('preview-status').textContent='正在產生預覽…';
  try{
    let options,path;
    if(file){const form=new FormData();form.append('file',file);options={method:'POST',body:form};path='/api/v1/rules/file';}
    else{options={method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})};path='/api/v1/rules';}
    const data=await request(path,options);
    if(sequence!==previewSequence)return;
    previewCache={file,text,mode:inputMode,data};
    if(data.source_document)renderMail(data.source_document);
    else if(file)$('mail-preview').replaceChildren(element('p','未取得預覽內容，請重新選檔或重試。','note'));
    if(data.status==='FAILED')$('preview-status').textContent='解析未成功，仍可查看已收到的原始文字。';
  }catch(error){if(sequence!==previewSequence)return;$('preview-status').textContent='預覽未完成：'+error.message;}
}
function inputChanged(){
  if(busy||sourceMode==='history')return;
  showReadingTab('mail');
  clearResultDetails();
  previewSequence++;previewCache=null;clearTimeout(previewTimer);
  $('result').replaceChildren(element('p','內容已更新，請開始分析以取得這封信的結果。','empty-state'));
  $('form-status').textContent='';
  if(inputMode==='text'&&$('email-text').value.trim())renderMail({source:'pasted_text',raw_text:$('email-text').value,parsed:null});
  previewTimer=setTimeout(refreshInputPreview,450);
}
$('email-text').addEventListener('input',()=>{if(inputMode==='text')inputChanged();});
$('analysis-form').addEventListener('submit',async event=>{
  event.preventDefault();if(busy)return;
  if(sourceMode==='history'){$('form-status').textContent='目前正在檢視歷史紀錄，請先開始新的分析。';return;}
  previewSequence++;clearTimeout(previewTimer);
  if(inputMode==='file'&&batchItems.length>1){await analyzeBatch('configured');return;}
  const file=inputMode==='file'?$('email-file').files[0]:null;
  const text=inputMode==='text'?$('email-text').value:'';
  if(!file&&!text.trim()){$('form-status').textContent='請選擇檔案或貼上郵件內容。';return;}
  if(file&&file.size>2000000){$('form-status').textContent='檔案超過 2 MB，請使用單封較小的郵件。';return;}
  const mode='configured';showReadingTab('mail');setBusy(true,'完整分析等待中…');
  $('result').replaceChildren(loadingState('正在等候完整分析結果；尚無安全結論。'));
  try{
    // Preview is optional: reuse only an exact source match and never hold analysis behind it.
    if(previewCache?.mode===inputMode&&previewCache.file===file&&previewCache.text===text)renderPreview(previewCache.data);
    else if(file){
      $('mail-preview').replaceChildren(element('p','已送出完整分析，信件預覽會隨結果更新。','note'));
      $('preview-status').textContent='正在等候完整信件解析與分析結果。';
    }else renderMail({source:'pasted_text',raw_text:text,parsed:null});
    let data;
    if(file){const form=new FormData();form.append('file',file);form.append('mode',mode);data=await request('/api/v1/analyses/file',{method:'POST',body:form});}
    else data=await request('/api/v1/analyses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text,mode})});
    renderResult(data);
    $('form-status').textContent=data.persistence?.state==='unconfirmed'?'尚未確認保存結果；請先查看分析紀錄，避免重複提交。':data.persistence?.state==='not_saved'?'本次結果未保存；請保留原始信件，確認原因後再提交。':data.status==='FAILED'?'分析未完成；結果已保存，可由分析紀錄確認原因。':'結果已保存，請留意模擬標記與人員判斷參考事項。';
  }catch(error){
    $('result').replaceChildren(element('div','未取得可用分析結果。'+error.message,'error-message'));
    $('form-status').className='form-status error';$('form-status').textContent=error.message;
  }finally{setBusy(false,$('form-status').textContent);}
});
$('email-file').addEventListener('change',()=>{prepareBatch();const selected=$('email-file').files.length>0;setBusy(false);$('clear-file').hidden=!selected;inputChanged();clearTimeout(previewTimer);refreshInputPreview();});
$('clear-file').addEventListener('click',()=>{$('email-file').value='';batchItems=[];batchInvalid='';renderBatch();$('clear-file').hidden=true;$('email-file').focus();inputChanged();});
let modelCheckRunning=false;
const connectionReasons={MODEL_STATUS_OFFLINE:'AI 服務離線，目前沒有可連通的端點',LLM_TEST_MODE_DISABLED:'網站未配置可用 AI，模擬僅供測試工具使用',LLM_NOT_CONFIGURED:'尚未設定 AI',LLM_CONFIGURATION_INVALID:'AI 設定無效',SIMULATED_ANALYSIS:'目前只設定離線模擬',MODEL_STATUS_AUTH_FAILED:'服務認證未通過',MODEL_STATUS_RATE_LIMITED:'服務暫時限流',MODEL_STATUS_UNAVAILABLE:'無法連線模型服務',MODEL_STATUS_TIMEOUT:'連線檢查逾時',MODEL_STATUS_MODEL_MISSING:'服務已連通，但設定的 A／B 模型不完整',MODEL_STATUS_INVALID:'模型清單回覆無效',MODEL_STATUS_UNSUPPORTED:'服務未提供模型清單，尚未確認模型可用性'};
async function checkModelConnection(){
  if(modelCheckRunning||busy)return;
  modelCheckRunning=true;$('check-model').disabled=true;
  $('model-connection-status').textContent='正在檢查 AI 連線…';
  try{
    const status=await request('/api/v1/models/status');
    $('model-connection').classList.toggle('ready',status.connected===true);
    if(status.connected===true){
      $('model-connection-status').textContent='AI 已連通，可開始分析。';
      const backups=Object.values(status.stages||{}).some(stage=>stage.active_endpoint_index>1);
      if(backups)$('model-connection-status').textContent='AI 已連通，目前使用備援端點。';
    }else{
      const reason=connectionReasons[status.reason_code]||'尚未確認 AI 可用，請檢查設定後重試。';
      $('model-connection-status').textContent=reason+(status.configuration_valid===true?'；連線設定有效，模型可用性仍待確認。':'');
    }
  }catch{$('model-connection').classList.toggle('ready',false);$('model-connection-status').textContent='無法完成 AI 連線檢查，請稍後重試。';}
  finally{modelCheckRunning=false;$('check-model').disabled=busy;}
}
$('check-model').addEventListener('click',checkModelConnection);


function renderReportDetails(sections) {
  const root=$('result-details');
  const navigation=element('div',undefined,'report-navigation');
  navigation.setAttribute('role','tablist');
  navigation.setAttribute('aria-label','報告章節');
  const groups=[
    {key:'reasons',label:'判斷理由',sections:[]},
    {key:'evidence',label:'原文證據',sections:[]},
    {key:'execution',label:'分析狀態',sections:[]}
  ];
  for (const block of sections) {
    const title=block.children[0]?.textContent||'';
    const group=['信件內容｜人工判讀','證據定位','本次擷取網址（不保存）'].includes(title)?1:
      ['信件中值得注意的內容','分析理由與證據','建議確認事項'].includes(title)?0:2;
    groups[group].sections.push(block);
  }
  const panels=groups.map(group=>{
    const panel=element('div',undefined,'report-pane');
    panel.setAttribute('id','report-pane-'+group.key);
    panel.setAttribute('role','tabpanel');
    panel.setAttribute('aria-labelledby','report-tab-'+group.key);
    panel.setAttribute('tabindex','0');
    panel.append(...group.sections);
    return panel;
  });
  const buttons=[];
  function select(index,focus=false) {
    panels.forEach((panel,i)=>{panel.hidden=i!==index;});
    buttons.forEach((button,i)=>{
      button.setAttribute('aria-selected',String(i===index));
      button.setAttribute('tabindex',i===index?'0':'-1');
    });
    if(focus)buttons[index].focus();
  }
  groups.forEach((group,index)=>{
    const button=element('button',group.label,'reading-tab');
    button.setAttribute('type','button');button.setAttribute('role','tab');
    button.setAttribute('id','report-tab-'+group.key);
    button.setAttribute('aria-controls','report-pane-'+group.key);
    button.addEventListener('click',()=>select(index));
    button.addEventListener('keydown',event=>{
      const directions={ArrowRight:(index+1)%3,ArrowLeft:(index+2)%3,Home:0,End:2};
      if(!(event.key in directions))return;
      event.preventDefault();select(directions[event.key],true);
    });
    buttons.push(button);navigation.append(button);
  });
  root.replaceChildren(navigation,...panels);select(0);
}
function reportReady(result) {
  return Boolean(result?.analysis_id)&&!['not_saved','unconfirmed'].includes(result.persistence?.state);
}
function updateExportControls() {
  $('export-current').disabled=exportBusy||!reportReady(currentReport);
  $('export-batch').disabled=exportBusy||batchRunning||!batchItems.some(item=>reportReady(item.result));
  $('export-selected').disabled=exportBusy||selectedReports.size===0;
  const separate=$('export-format').value==='zip';
  $('export-format-note').textContent=selectedReports.size?separate?'會下載一個 ZIP 壓縮檔，解壓縮後有 '+selectedReports.size+' 份 PDF，每封信各一份。':'會下載一份 PDF，依序包含所選的 '+selectedReports.size+' 封信件報告。':'先勾選信件，再下載報告。每次最多 20 封，可跨頁選取。';
  $('selection-count').textContent='已選 '+selectedReports.size+' / 20 份';
  $('select-page').disabled=exportBusy||!historyItems.length;
  if(currentReport&&!reportReady(currentReport))$('export-status').textContent='此結果尚未確認保存，請先查回紀錄後匯出。';
  $('select-page').checked=historyItems.length>0&&historyItems.every(item=>selectedReports.has(item.analysis_id));
}
async function downloadReports(ids,format='pdf',statusId='export-status') {
  if(exportBusy||!ids.length)return;
  if(ids.length>20){$(statusId).textContent='每次最多匯出 20 份，請減少選取。';return;}
  exportBusy=true;updateExportControls();
  $(statusId).textContent='正在產出 '+ids.length+' 份報告…';
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),90000);
  try {
    const response=await fetch('/api/v1/reports/export',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({analysis_ids:ids,format}),cache:'no-store',signal:controller.signal
    });
    if(!response.ok)throw new Error(response.status===404?'部分紀錄不存在，請重新整理後再選取。':'匯出未完成，請確認服務與資料庫後重試。');
    const blob=await response.blob();
    const url=URL.createObjectURL(blob);
    const anchor=element('a');anchor.href=url;anchor.download=response.headers.get('Content-Disposition')?.match(/filename="([^"]+)"/)?.[1]||'phishshield-reports.'+format;
    document.body.append(anchor);anchor.click();anchor.remove();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
    $(statusId).textContent='已送出下載，請查看瀏覽器的下載紀錄。';
  } catch(error) {$(statusId).textContent=error.name==='AbortError'?'匯出等待逾時，請稍後重試。':error.message;}
  finally {clearTimeout(timer);exportBusy=false;updateExportControls();}
}
$('export-current').addEventListener('click',()=>downloadReports([currentReport.analysis_id]));
$('export-batch').addEventListener('click',()=>downloadReports(batchItems.filter(item=>reportReady(item.result)).map(item=>item.result.analysis_id)));
$('export-format').addEventListener('change',updateExportControls);
$('export-selected').addEventListener('click',()=>downloadReports([...selectedReports],$('export-format').value,'history-export-status'));
$('select-page').addEventListener('change',()=>{
  if($('select-page').checked&&new Set([...selectedReports,...historyItems.map(item=>item.analysis_id)]).size>20){
    $('history-export-status').textContent='每次最多選取 20 份。';$('select-page').checked=false;return;
  }
  for(const item of historyItems){if($('select-page').checked)selectedReports.add(item.analysis_id);else selectedReports.delete(item.analysis_id);}
  for(const [id,checkbox] of historyCheckboxes)checkbox.checked=selectedReports.has(id);
  updateExportControls();
});
$('history-search').addEventListener('submit',event=>{
  event.preventDefault();
  const start=$('history-from').value,end=$('history-to').value;
  if(start&&end&&start>end){$('history-status').textContent='開始日期須早於或等於結束日期。';return;}
  historyFilters={query:$('history-query').value.trim(),date_from:start,date_to:end};
  selectedReports.clear();page=1;updateExportControls();loadHistory();
});
$('clear-search').addEventListener('click',()=>{
  for(const id of ['history-query','history-from','history-to'])$(id).value='';
  historyFilters={};selectedReports.clear();page=1;updateExportControls();loadHistory();
});
async function openHistory(item) {
  if(busy)return;
  sourceMode='history';clearInputSources();setBusy(true,'載入紀錄中…');
  showTab('analyze');showReadingTab('mail');previewSequence++;clearTimeout(previewTimer);
  $('mail-preview').replaceChildren(loadingState('正在載入信件…'));
  $('result').replaceChildren(loadingState('正在載入紀錄…'));
  try {
    renderResult(await request('/api/v1/analyses/'+encodeURIComponent(item.analysis_id)));
    setBusy(false,'正在檢視歷史紀錄；若要分析其他信件，請開始新的分析。');
  } catch(error) {
    $('mail-preview').replaceChildren(element('p','無法載入此紀錄的信件內容。','note'));
    $('result').replaceChildren(element('div',error.message,'error-message'));setBusy(false,error.message);
  }
}
async function loadHistory() {
  if(busy)return;
  const sequence=++historySequence,requestedPage=page,requestedSize=pageSize;
  $('history-body').replaceChildren();historyItems=[];historyCheckboxes.clear();updateExportControls();
  $('previous-page').disabled=true;$('next-page').disabled=true;$('page-select').disabled=true;
  $('page-label').textContent='第 '+requestedPage+' 頁';
  $('history-status').replaceChildren(loadingState('讀取紀錄中…'));
  const filters=Object.entries(historyFilters).filter(([,value])=>value)
    .map(([key,value])=>'&'+key+'='+encodeURIComponent(value)).join('');
  try {
    const data=await request('/api/v1/analyses?page='+requestedPage+'&page_size='+requestedSize+filters);
    if(sequence!==historySequence)return;
    page=requestedPage;total=data.total;historyItems=data.items;
    $('history-body').replaceChildren();
    for(const item of data.items) {
      const row=element('tr');
      const time=new Intl.DateTimeFormat('zh-TW',{timeZone:'Asia/Taipei',dateStyle:'short',timeStyle:'short'}).format(new Date(item.created_at));
      const first=element('td');const label=element('label',undefined,'checkbox-label');
      const checkbox=element('input');checkbox.type='checkbox';checkbox.checked=selectedReports.has(item.analysis_id);
      historyCheckboxes.set(item.analysis_id,checkbox);
      checkbox.setAttribute('aria-label','選取 '+(item.subject||time)+' 的報告');
      checkbox.addEventListener('change',()=>{
        if(checkbox.checked&&selectedReports.size>=20){checkbox.checked=false;$('history-export-status').textContent='每次最多選取 20 份。';return;}
        if(checkbox.checked)selectedReports.add(item.analysis_id);else selectedReports.delete(item.analysis_id);
        updateExportControls();
      });
      label.append(checkbox,element('span',time));first.append(label);
      if(item.subject)first.append(element('p',item.subject,'history-subject'));
      if(item.sender)first.append(element('p',item.sender,'note'));
      row.append(first,element('td',modelLabel(item)),element('td',(item.final_classification==='UNKNOWN'?(threatCount(item)>0?'已偵測可疑釣魚特徵｜交由人員判斷':'交由人員判斷'):labels[item.final_classification])||'尚未完成'),element('td',item.simulation?'離線模擬':'AI 分析'));
      const cell=element('td');const button=element('button','開啟','secondary');
      button.addEventListener('click',()=>openHistory(item));cell.append(button);row.append(cell);
      for(const [index,field] of ['時間／信件（台北）','模型分析','分類','分析模式','查看'].entries())row.children[index].setAttribute('data-label',field);
      $('history-body').append(row);
    }
    if(!data.items.length){
      const row=element('tr',undefined,'history-empty');const cell=element('td');cell.setAttribute('colspan','5');
      cell.append(element('h3',filters?'沒有符合條件的報告':'還沒有分析紀錄','title-3'),element('p',filters?'調整日期或關鍵字後再搜尋。':'完成第一封信的分析後，即可在這裡重新查看。','note'));
      row.append(cell);$('history-body').append(row);
    }
    $('history-status').textContent=total?'共 '+total+' 筆紀錄。':filters?'沒有符合條件的報告。':'目前沒有分析紀錄。';
    $('page-label').textContent='第 '+page+' 頁';$('previous-page').disabled=page===1;$('next-page').disabled=page*pageSize>=total;
    updatePagination();updateExportControls();
  } catch(error) {
    if(sequence!==historySequence)return;
    total=0;$('history-status').textContent=error.message;$('history-body').replaceChildren();
    $('page-label').textContent='第 '+requestedPage+' 頁';$('previous-page').disabled=requestedPage===1;$('next-page').disabled=true;$('page-select').disabled=true;
  }
}
function updatePagination(){
  const pages=Math.max(1,Math.ceil(total/pageSize));
  const select=$('page-select');select.replaceChildren();
  for(let value=1;value<=pages;value++){const option=element('option','第 '+value+' 頁');option.value=String(value);select.append(option);}
  select.value=String(page);select.disabled=total===0;
  $('page-size').value=String(pageSize);
}
$('page-size').addEventListener('change',()=>{
  const size=Number($('page-size').value);
  if(![10,20,50,100].includes(size))return;
  pageSize=size;page=1;loadHistory();
});
$('page-select').addEventListener('change',()=>{
  const next=Number($('page-select').value);
  if(!Number.isInteger(next)||next<1||next>Math.max(1,Math.ceil(total/pageSize)))return;
  page=next;loadHistory();
});
$('tab-analyze').addEventListener('click',()=>showTab('analyze'));
$('tab-history').addEventListener('click',()=>{showTab('history');loadHistory();});$('refresh-history').addEventListener('click',loadHistory);$('previous-page').addEventListener('click',()=>{if(page>1){page--;loadHistory();}});$('next-page').addEventListener('click',()=>{if(page*pageSize<total){page++;loadHistory();}});
$('privacy-link').addEventListener('click',()=>{$('privacy').open=true;});
$('usage-link').addEventListener('click',()=>{$('usage-note').open=true;});
syncInputMode();
setBusy(false);
checkModelConnection();
(async()=>{try{await request('/api/v1/health');$('health').textContent='服務與資料庫就緒';$('health').classList.add('ready');const versions=await request('/api/v1/versions');const product=versions.product||'1.0.0';$('version-note').textContent='PhishShield '+product;}catch{$('health').textContent='服務或資料庫尚未就緒';}})();
