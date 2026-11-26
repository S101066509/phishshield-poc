# PhishShield 1.0.0 API 使用說明

目前範圍為本地展示／Demo POC MVP。Compose部署、資料庫更新與模型端點設定見 [README](../README.md)。API 路徑中的 `v1` 是路由名稱；目前版本為 **1.0.0**。請求與回應的完整欄位可在啟動後的 `/docs` 或 `/openapi.json` 查看。

configured模式使用 `IsolatedDualLLMPipeline`／`structured_dual`／`core_slots_1`八類觀察流程。模型A擷取觀察，程式轉為受控資料，再交由模型B判斷分類與支持理由；既有其他格式的分析紀錄可按原資料格式讀取。

模型逾時仍回報未完成／UNKNOWN。失敗回覆的`model_diagnostics.calls`可含`latency_ms`、`timeout_kind`（connect／pool／read／write／unspecified／call_deadline／endpoint_deadline／total_deadline）、`output_token_parameter`及三項請求SHA-256指紋，供API除錯；不包含原文或模型回覆，也不呈現在讀者PDF正文。舊紀錄可能缺少這些欄位，不能推定當時的逾時來源。Connect／Pool timeout可有限重試，Read／Write／未知逾時及生成期限停止，不重送同一判斷。端點參數見[連接教學](project-endpoint-setup.md)。

## Swagger 與入口

| 用途 | 網址 |
|---|---|
| 工作台 | http://127.0.0.1:8000/ |
| Swagger | http://127.0.0.1:8000/docs |
| Swagger 別名 | http://127.0.0.1:8000/swagger，導向 `/docs` |
| OpenAPI JSON | http://127.0.0.1:8000/openapi.json |
| 健康檢查 | http://127.0.0.1:8000/api/v1/health |
| 目前版本 | http://127.0.0.1:8000/api/v1/versions |
| AI 可用性 | http://127.0.0.1:8000/api/v1/models/status |

Swagger 展開端點後，依 **Try it out → 填入資料 → Execute** 操作。完整分析 POST 會呼叫已設定模型，並保存原文及結果；預覽只解析與跑規則。`/api/v1` 本身沒有列表頁。

## 端點

| 方法與路徑 | 輸入 | 用途 |
|---|---|---|
| GET `/api/v1/health` | 無 | 服務、資料庫與 migration 是否就緒 |
| GET `/api/v1/versions` | 無 | 目前產品／分析／DB／UI／報告識別 |
| GET `/api/v1/models/status` | 無 | 唯讀查模型清單，不推論 |
| POST `/api/v1/rules` | JSON text、可選 mode | 文字規則預覽，不保存 |
| POST `/api/v1/rules/file` | multipart file | 單封 EML／TXT 預覽，不保存 |
| POST `/api/v1/analyses` | JSON text、可選 mode | 完整文字分析並保存 |
| POST `/api/v1/analyses/file` | multipart file、可選 mode | 單封 EML／TXT 完整分析並保存 |
| GET `/api/v1/analyses` | page、page_size、query、date_from、date_to | 分頁歷史摘要 |
| GET `/api/v1/analyses/{analysis_id}` | UUID | 原結果、原文與證據 |
| GET `/api/v1/analyses/{analysis_id}/report.pdf` | 已保存 UUID | 單筆 PDF |
| POST `/api/v1/reports/export` | JSON analysis_ids、format | 合併 PDF／個別 PDF ZIP |

## 設定與連線檢查

首次連接請看[端點連接教學](project-endpoint-setup.md)，依序完成設定、重新建立容器與狀態檢查。

本機 Ollama 與外部 OpenAI 相容服務共用根 `.env`，程序環境變數優先，修改後重啟。A／B 使用各自排序端點池 `PHISHSHIELD_LLM_ENDPOINTS_A`／`PHISHSHIELD_LLM_ENDPOINTS_B`，每階段 1–10 組，包含 endpoint、model、可選 api_key／provider／thinking。設定範例與傳輸政策見 [README](../README.md#ai-設定) 及 [.env.example](../.env.example)。

全域 `PHISHSHIELD_LLM_TEMPERATURE=0`、`PHISHSHIELD_LLM_SEED=42` 為預設採樣設定，適用於 A／B 所有端點。`temperature` 範圍為 0–2；環境設定 `PHISHSHIELD_LLM_SEED=null`（Python 為 `seed=None`）時省略請求的 seed。這些設定由後端管理，分析 API 不接受逐次覆寫。低溫與固定 seed 可減少重跑波動，不保證更高辨識率或跨服務、硬體及版本的逐位元重現。

健康檢查 `status=ready`、`database=ready` 只代表應用與 DB 就緒。模型檢查的欄位如下：

| 欄位 | 意義 |
|---|---|
| configuration_valid | 配置通過端點／模型設定檢查 |
| connected | A／B 各找到精確匹配的模型 ID |
| service_reachable | 至少收到一個 HTTP 回應，認證錯誤也可能為 true |
| availability | available、missing、unconfirmed 或 offline |
| stages.a／stages.b | 可用性、第一個可用端點 index、端點數與逐端點檢查結果 |
| stages 的 endpoints[] | index、availability、service_reachable、reason_code，不含 URL／Key |
| check_kind | model_availability_not_inference |

檢查有 4 秒總期限，同次 URL＋Key 相同的查詢共用，不跨請求快取。只查 `/models`，不發送郵件、不推論、不存歷史；模型清單不支援或逾時代表未確認，不單獨禁止配置有效的分析。清單檢查不是永久路由，推論仍從第一組開始，也不保證之後成功。

完整分析只對暫時斷線、逾時及指定可恢復錯誤有限重試／同階段備援，所有嘗試共用總期限。認證、格式、引用與理由支持錯誤不切換端點；沒有 Fake 或格式恢復備援。全部不可用回 LLM_ENDPOINTS_OFFLINE，期限先到可為 LLM_TIMEOUT／ANALYSIS_TIMEOUT。

## 預覽與完整分析

### 規則預覽

```sh
curl -sS http://127.0.0.1:8000/api/v1/rules \
  -H 'Content-Type: application/json' \
  --data '{"text":"您好，本週會議紀錄已整理完成。"}'

curl -sS http://127.0.0.1:8000/api/v1/rules/file \
  -F 'file=@mail.eml'
```

成功回 `preliminary=true`、`phase=2`、`final_classification=null`、findings、review_required、source_document 與 transient_urls。沒有安全分類或歷史保存。已捕捉的 Parser／規則失敗可仍回 HTTP 200，必須讀 `status`／`error_code`；不能只看 HTTP 判斷成功。文字 mode 沿用輸入 Schema，但預覽不呼叫模型。

### 文字完整分析

```sh
curl -sS --max-time 310 http://127.0.0.1:8000/api/v1/analyses \
  -H 'Content-Type: application/json' \
  --data '{"text":"您好，本週會議紀錄已整理完成。","mode":"configured"}'
```

`AnalyzeRequest` 只接受 `text`（1–1,000,000 字元）與 `mode`，額外欄位拒絕。產品使用預設的 configured，由後端端點池執行；Schema 保留的 fake 值在一般部署停用，回 LLM_TEST_MODE_DISABLED。正文仍受 2,000,000 bytes、Parser 文字及模型預算限制。看似 Header 的貼上文字保持正文模式。

### EML／TXT 完整分析

```sh
curl -sS --max-time 310 http://127.0.0.1:8000/api/v1/analyses/file \
  -F 'file=@mail.eml' \
  -F 'mode=configured'
```

每次只接受一個 file，副檔名不分大小寫。EML 解析單封 MIME 郵件；TXT 接受 UTF-8／UTF-8 BOM，以正文處理。單檔最多 2,000,000 bytes；HTTP body 預設 2,100,000 bytes，含 multipart 包裝，接收期限 10 秒。直接上傳 MBOX、MSG、PDF 等不支援格式會拒絕。

工作台批次是逐封呼叫本端點，最多 20 封、合計 20,000,000 bytes；停止只影響未送出的信。API 沒有背景批次工作或先回 job ID 的契約。

### 預設期限

完整分析的 `PHISHSHIELD_ANALYSIS_TIMEOUT_SECONDS` 預設 45 秒、最多 300 秒，涵蓋解析、規則、模型、說明、原文及保存。模型單次 10 秒、A／B 共用 30 秒；Parser 5 秒；預覽整體 8 秒。保存回覆異常另以原 ID／hash 查回，`PHISHSHIELD_RECONCILIATION_TIMEOUT_SECONDS` 預設 1 秒、最多 5 秒。取消回收可能使實際回應包含必要清理時間，不會重跑分析或自動重送交易。

模型 data 與完整請求包裝上界各預設 256,000 bytes，輸出預留 2,048 tokens、回覆上限 65,536 bytes。字元估算不是精確 tokenizer，只有確認實際 runner 容量才設定 `PHISHSHIELD_LLM_EFFECTIVE_CONTEXT_TOKENS`，未設定標 unavailable。以上是程式預設，部署以環境為準。

## 如何閱讀回覆

| 欄位 | 意義 |
|---|---|
| status／analysis_completed | 整體流程完成或未完成 |
| final_classification | SAFE、SUSPICIOUS、PHISHING、UNKNOWN |
| analysis_id | 本次操作 UUID，保存與否另看 persistence |
| model_analysis | 是否啟動、模型是否完成驗證、受控原因與規則計數 |
| analysis_reliability | 核心狀態、展示狀態、來源coverage、首輪／逐次預算及可得用量；事件紀錄另有A提取狀態 |
| analysis_explanation | 現行程式依已驗證的八類觀察與明選理由整理摘要、原文引用及確認建議 |
| coverage | scope=normalized_registry，表示 Parser 可分析材料的涵蓋範圍 |
| source_document | 原始 UTF-8 顯示文字、parsed、閱讀正文與證據對照 |
| rule_findings／rule_signal_summary | 規則訊號，不等同可信惡意判定 |
| failed_phase／errors | 未完成階段及受控代碼 |
| persistence | state=saved／not_saved／unconfirmed，reconciled 表示是否異常查回 |
| created_at／started_at／completed_at | UTC 時間；完成是計算／覆核完成，不是 commit 時間 |
| latency_ms／latency_scope | 分析至覆核的實測耗時，不含保存、查回與網路；未知 null |
| api_version／decision_version／versions | 本筆結果的契約／模型設定識別，不能用目前版本覆蓋舊紀錄 |
| analysis_trace／model_diagnostics／input_diagnostic | 工程追溯、受限失敗診斷與資源限制；一般報告不展示 |

`COMPLETED + UNKNOWN` 是有效資訊不足／人員判讀；`FAILED + UNKNOWN` 是未完成分析。歷史資料中的 simulation=true 表示模擬結果，不是實際安全結論。`model_analysis.completed` 不能代替整體完成或已保存。

現行主線為 `structured_dual`／`core_slots_1`。A填寫authentication、credential_request、urgency_fear、impersonation、generic_salutation、url_deception、language、analysis_override八類觀察的受控assessment及引用；observed表示A認為該風險訊號成立。程式重驗引用、重編代號，建立 `structured_handoff_2`並重算規則布林／計數等程式事實。B只讀封閉交接，選取分類、理由槽與不確定碼，不接觸原文或自由摘要。一次分析為A一次、B一次邏輯推論，沒有原文、事件或其他格式備援。

`analysis_trace`的 `method`、`judgment_format`及交接contract區別資料形狀；目前版本都為1.0.0，不代表形狀相同。現行八槽trace保存 `structured_handoff_2`交接、evidence_map、`core_slots_1`決策及coverage。這些是工程資料，原文反向對照只留在後端保存及人員閱讀，不提供給B。

有效UNKNOWN的`analysis_explanation.model.abstention`可包含程式從已驗證核心整理的棄權摘要：未提取到風險、已提取但未採用、已採用參考仍未形成結論。`summary`及`next_steps`是人員文字，`model_internal_reason_available=false`表示沒有模型內部理由；不改最終分類。舊資料或不適用時可缺欄，前端／PDF沿用rationale。

工程用`model_diagnostics.calls[*].transport_diagnostic`可為null，或只含固定category、HTTP status、白名單parameter及timeout_phase；不含原始錯誤訊息／body／Key。503後恢復成功也可保留診斷，成功分類不因此改成失敗。舊缺值不回填，這些工程代碼不加入讀者報告正文。

現行回覆的 `analysis_explanation.reason_source`與 `presentation.source`為 `deterministic_observations`。保留 `model.rationale`／`model.explanations`欄名是為閱讀相容；內容由程式依已驗證的核心、八類觀察及原文引用整理，**不是模型B原話，也未外部查證**。

歷史 `structured_event_dual`／`event_facts_core_1`仍按事件契約閱讀，其trace可保存 `event_extraction_1`、`event_handoff_1`及事件決策，說明來源為 `deterministic_event_facts`。proposal與legacy也保留原義；讀取不改寫結果，不替八槽資料補造事件。事件方法不是configured預設，也不在八槽失敗時啟用。

`presentation.status` 為 complete／degraded／legacy／unavailable；模板故障可降級並保留有效核心分類及證據，必要證據無法還原則 FAILED／UNKNOWN。`analysis_reliability.core_status` 與展示／保存分開；有效核心後保存逾時，核心可保留 valid，但整體 FAILED，不沿用分類。

`coverage`只表示normalized Registry的來源送達情況，不宣稱附件或全部raw EML已分析，也不表示A理解完整。事件歷史的 `analysis_reliability.semantic_extraction`另記availability、claimed_status、semantic_completeness、規範化前事件／關係數及factual_recall=unavailable；這些是當時受控紀錄，不是八槽新增事件計數，也不是人工事實召回率。未記錄表示unavailable，不補成完整提取。

現行八槽SAFE須只明選NO_RISK_OBSERVED並綁定已檢視陰性觀察，沒有任何observed／uncertain，且來源與規則完整、無規則命中／警告／覆核。PHISHING至少明選一項受支持的非authentication模型風險理由；SUSPICIOUS亦可由有引用支持的RISKY_ATTACHMENT單獨成立，單獨附件訊號不能支持PHISHING。沒有具體userinfo／IP host指標的單獨uncertain網址觀察，不能支持這兩種風險分類。這些是程式檢查的最低支持資格，不代表已以程式完整強制B提示中的風險強度分級。A全陰性不代表已驗真安全；有效UNKNOWN可保留支持觀察，結構／引用／支持錯誤仍是FAILED，不轉為成功UNKNOWN。`format_recovery`固定disabled，沒有第三次說明模型。

目前 B 的有效系統提示會在英文任務文字後附上本次完整輸出 Schema，內容與 `response_format` 相同；只含封閉 enum／引用代號，不新增郵件原文。呼叫診斷的 `request_prompt_sha256` 記錄含 Schema 的實際提示，因此會隨本次 Schema 改變；固定任務文字的指紋不是每筆有效提示指紋。預算中的 system 與 response schema 分別如實計算，輸出預留使用該階段實際額度。A／B 上限由後端 `.env` 分別設定，公開請求不能逐次覆寫。

`FAILED`／`LLM_OUTPUT_INVALID` 且截斷診斷一致時，畫面與 PDF 會說明「模型輸出達長度上限，回覆未完成」。缺少歷史診斷或其他格式錯誤仍採一般未完成說明，不猜測原因，也不採用半份分類。

診斷只保存固定原因、已知欄位路徑及計數，不保存 raw reply、例外、郵件值或思考。支持明細不含觀察／引用 ID；原文及 `analysis_trace` 則是另行保存的敏感資料。缺少歷史診斷表示未記錄，不能推定原因。

## 系統提示與診斷

目前A／B使用固定英文系統提示，不提供中文候選或提示語言切換，也不依模型名稱自動切換。公開分析API只接受既有text／file與mode，不接受逐次提示語言或外部handoff。

可用的模型呼叫診斷以`request_prompt_sha256`記錄實際送出提示的指紋；目前B的指紋包含本次輸出Schema。診斷可能未記錄或不可得，不由缺值推定當時提示。這些診斷資料供API除錯，不加入畫面報告或PDF。

## 歷史搜尋與閱讀

```sh
curl -sS 'http://127.0.0.1:8000/api/v1/analyses?page=1&page_size=20'
curl -sS 'http://127.0.0.1:8000/api/v1/analyses/11111111-1111-4111-8111-111111111111'
```

示例 UUID 需換成實際 analysis_id。列表回 page、page_size、total、items；單筆才提供完整原文及說明。

| 參數 | 契約 |
|---|---|
| page | 預設 1，範圍 1–100000 |
| page_size | 預設 20，範圍 1–100 |
| query | 最多 100 字，主旨、寄件者、正文、原始顯示文字及 rationale 的不分大小寫片段比對，`%`／`_` 按字面 |
| date_from／date_to | YYYY-MM-DD，台北分析 created_at 日期，含起訖日；不是郵件 Date |

先套用全部條件，再按 created_at／ID 倒序分頁；total 是篩選後總數。開始日晚於結束日為 INVALID_DATE_RANGE／422。列表只取摘要，包含可空的 model_analysis、analysis_reliability 與 coverage。

單筆只讀既有結果，不重跑模型、不改寫舊 DB JSON。舊 source_document 可能 null，缺少新欄位或版本表示當時未知，舊 latency_scope 缺少時耗時視為未知；不補成 1.0.0 核心。重新分析請重新提交原始輸入，產生新紀錄。

## PDF 與 ZIP

單筆使用 `GET /api/v1/analyses/{analysis_id}/report.pdf`，批次使用 `POST /api/v1/reports/export`。完整請求示例的 UUID 需替換為已保存紀錄：

```json
{
  "analysis_ids": ["11111111-1111-4111-8111-111111111111"],
  "format": "pdf"
}
```

analysis_ids 為 1–20 個 UUID，去重後保留首次出現順序，任一不存在回 404。format=pdf 合併成一份；zip 為每筆一份 PDF。回覆為 attachment，Content-Type 為 application/pdf 或 application/zip。伺服器記憶體產生，瀏覽器下載，不重新分析。

報告包含分類、理由、必要執行／範圍提示、原文及證據節錄。原文最多 3,000 字、每則證據最多 2,000 字、一般段落最多 4,000 字，過長提示回網站閱讀；缺字或不可見格式字元使用 U+ 編碼。單筆、合併與 ZIP 共用相同閱讀邏輯，工程版號、模型識別、UUID、hash、trace 不放在一般報告或檔名。

## HTTP、保存與重送

| HTTP | 含義 |
|---|---|
| 200 | 查詢、下載或預覽；預覽仍需檢查 JSON 失敗狀態 |
| 201 | 完整分析流程完成並保存，包含有效 UNKNOWN |
| 400 | Content-Length 無效 |
| 403 | Origin 與目前 Host 不符 |
| 404 | 指定分析不存在 |
| 408 | 請求本文接收逾時 |
| 413 | 檔案、解析或 HTTP 大小超限 |
| 415 | 不支援 Content-Type／副檔名 |
| 422 | 欄位、mode、UUID、分頁／日期無效，或 Phase 1 解析失敗 |
| 503 | 模型、決策、應用或資料庫未完成／不可用 |

請求邊界拒絕通常沒有 analysis_id 或 persistence；框架拒絕可能有不同回覆形狀。進入完整分析後的 FAILED 仍可已保存。`saved` 才確認保存，`not_saved` 為未存，`unconfirmed` 為未知；`reconciled=true` 表示異常查回確認，回的是已存原結果。有 ID 不代表保存成功。

網路中斷或 unconfirmed 時先用 ID 查歷史，再決定重送。後端不會自動重送交易，相同 POST 會建立新 ID，也不按 hash 去重。

目前限制本機 Host（localhost／127.0.0.1）及同源 Origin；工作台與 Swagger 同站操作。沒有多使用者認證或公開部署驗收。原文與理由會保存在本機 DB，遠端 A 會接收郵件材料；完整保存及隱私邊界見 [README](../README.md#資料保存與限制)。
