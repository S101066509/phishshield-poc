# PhishShield 1.0.0

PhishShield 是在本機執行的郵件風險分析工作台。匯入 EML／TXT 或貼上信件正文後，可對照原文、風險分類、分析理由與證據，並查詢歷史紀錄、下載 PDF 報告。

**本專案為概念驗證（PoC），目前版本為 1.0.0，供本機展示與流程驗證使用。** 系統結合規則檢查與雙階段 AI：模型 A 從信件擷取風險觀察，程式將其轉為受控資料，模型 B 依這些資料判斷，再由程式核對引用與支持依據。分析結果協助人員判讀，並非安全保證。

[開始使用](#開始使用) · [安裝與啟動](#安裝與啟動) · [端點連接教學](docs/project-endpoint-setup.md) · [AI 設定](#ai-設定) · [結果怎麼看](#結果怎麼看) · [API 與報告](#api-與報告)

## 可以做什麼

- **信件分析**：解析信件正文、選定標頭、HTML 文字、網址及附件名稱等資訊，檢查憑證要求、急迫威脅、網址偽裝、身分冒用及干預分析的內容。
- **批次處理**：同時選取多封 EML／TXT，依序分析並分別保存，每批最多 20 封。
- **原文對照**：「信件與結果」呈現正文及摘要；「詳細結果」可切換查看理由、證據與確認事項。
- **歷史搜尋**：依台北日期及主旨、寄件者、內文、判斷摘要中的關鍵字片段查詢，支援分頁與每頁筆數選擇。
- **報告下載**：下載單筆或合併 PDF，也可將多筆報告以每封一份 PDF 的 ZIP 下載至本機。
- **跨尺寸工作台**：原生 HTML／CSS／JavaScript 介面，依手機、平板、筆電與桌面寬度調整版面；無須前端編譯。
- **API 操作**：提供 REST API、同站 Swagger 與 OpenAPI JSON。

## 開始使用

1. 開啟工作台，在「上傳檔案」與「貼上文字」標籤中選擇輸入方式。
2. 匯入後會自動產生文字與初步規則預覽；這一步不呼叫模型，也不保存分析紀錄。
3. 按「開始分析」。畫面會顯示處理中狀態；批次另顯示逐封進度與清單。
4. 在「信件與結果」先看結論，再切換「詳細結果」核對理由及原文證據。
5. 到「分析紀錄」搜尋、重新開啟已保存結果，或勾選報告下載。

網站使用後端設定的 AI，模型與端點由管理者在 `.env` 配置，介面不提供模型選擇或設定頁。匯入區可檢查 AI 連線；檢查成功表示可列出對應模型，不等於已完成推論測試。

### 支援的輸入

| 輸入方式 | 處理方式 |
|---|---|
| `.eml` | 單封 MIME 郵件，可保留寄件者、主旨、正文及連結等上下文 |
| `.txt` | UTF-8 或 UTF-8 BOM，當作信件正文 |
| 貼上文字 | 當作正文；看似標頭或 HTML 的文字不會自動轉成 EML |
| 混合選取 EML／TXT | 瀏覽器逐封提交，每封有獨立結果與保存紀錄 |

副檔名不分大小寫。單封輸入上限為 **2,000,000 bytes**；工作台每批最多 **20 封**、合計 **20,000,000 bytes**。文字 API 另限制最多 1,000,000 字元，仍須通過輸入與請求大小檢查。

批次佇列只存在目前頁面。按「停止待處理」會讓正在分析的信件完成，其餘不再送出；重新整理頁面後需重新選取尚未處理的檔案。已保存結果仍可從分析紀錄開啟。

MSG、PST、MBOX、獨立 HTML、PDF、Office、圖片與壓縮檔不接受為分析輸入。附件僅保留中繼資料，不執行附件或分析附件內容。

## 安裝與啟動

以下指令皆從**專案根目錄**執行。建議使用 Docker Compose 啟動工作台與 PostgreSQL，宿主機無須安裝 Python；AI 模型服務與權重另行準備，不包含在應用映像中。

### Docker Compose（建議）

1. 安裝並啟動 Docker Desktop，或相容的 Docker Engine 與 Docker Compose V2。
2. 首次設定時複製範本；已有 `.env` 時編輯原檔，填妥[AI 設定](#ai-設定)。

```sh
cp -n .env.example .env
```

3. 建置並啟動：

```sh
docker compose up -d --build
```

Compose 啟動 PostgreSQL，待資料庫健康後，由應用容器更新資料庫並啟動工作台。即使尚未填妥 AI 端點，也可開啟介面與使用規則預覽；完整 AI 分析需先配置可用服務。

| 入口 | 網址 |
|---|---|
| 郵件分析工作台 | http://127.0.0.1:8000/ |
| Swagger | http://127.0.0.1:8000/docs |
| OpenAPI JSON | http://127.0.0.1:8000/openapi.json |
| 服務與資料庫健康檢查 | http://127.0.0.1:8000/api/v1/health |

健康檢查回傳 `status=ready`、`database=ready`，表示服務與資料庫就緒；AI 連線另由工作台檢查。查看應用輸出或停止容器：

```sh
docker compose logs -f app
docker compose stop
```

模型設定仍放在**同一份根目錄 `.env`**。容器會使用 Compose 內的 PostgreSQL 位址；本機 Ollama 的 loopback 位址會在容器程序內轉為宿主機連線位址，原 `.env` 不改寫。外部 HTTPS 端點沿用原設定。容器需能連到宿主機上的模型服務，Ollama 與其權重須先另行啟動及安裝。

PostgreSQL 17 的宿主機埠保留為 `127.0.0.1:55432`。歷史保存在名為 `development-db` 的 Docker 資料卷；此名稱不是專案資料夾，移除資料卷會刪除歷史。修改 `.env` 後應重新建立應用容器，讓新環境設定生效：

```sh
docker compose up -d --force-recreate app
```

### 原生 Python（可選）

此方式需 pyenv／pyenv-virtualenv 與 Python 3.12。以下以 macOS 及首次建立環境為例；已有 `phishing_detection` 環境時直接使用既有環境。

```sh
pyenv install -s 3.12.11
pyenv virtualenv 3.12.11 phishing_detection
pyenv local phishing_detection
pyenv exec python -m pip install -r requirements.txt
pyenv exec python -m pip check
```

程式會自動讀取根目錄 `.env`，無須 `source` 或 `export`；同名程序環境變數優先。可沿用 Compose 的 PostgreSQL，只啟動資料庫，再執行資料庫更新與後端：

```sh
docker compose up -d --wait postgres
PYTHONPATH=backend pyenv exec python -m alembic -c backend/alembic.ini upgrade head
pyenv exec python -m uvicorn app.main:create_app --factory --app-dir backend --host 127.0.0.1 --port 8000 --no-access-log
```

原生後端使用 `127.0.0.1:55432/phishshield`、使用者 `phishshield` 的預設資料庫連線。Compose 的資料庫使用本機展示用 trust 認證，僅綁定本機介面。若應用容器已占用 8000，請先停止 `app` 容器，避免兩種啟動方式爭用同一個埠。Uvicorn 在目前終端機執行，按 Ctrl+C 停止；修改 `.env` 後重新啟動原生後端。

上述方式目前供本機使用，其他平台及公開部署須另外確認。

## AI 設定

第一次設定請按[端點連接教學](docs/project-endpoint-setup.md)操作：選擇本機Ollama或外部API、填寫同一份.env、重新建立應用容器，再檢查A／B模型狀態。

Ollama 與外部服務使用**同一份根目錄 `.env`**。服務須提供 OpenAI 相容 Chat Completions，並支援本系統使用的嚴格 JSON Schema 輸出；相容 API 名稱相同，不代表所有模型或服務都支援同一組參數。

### 本機 Ollama

確認 Ollama 已啟動，使用 `ollama list` 查看完整模型 ID；需要時在另一個終端機執行 `ollama serve`。以下以 `gemma4:e4b` 為例，請按實際已安裝模型修改：

```dotenv
PHISHSHIELD_LLM_ENDPOINTS_A='[{"endpoint":"http://127.0.0.1:11434/v1","model":"gemma4:e4b","api_key":"","thinking":false,"output_token_parameter":"max_tokens"}]'
PHISHSHIELD_LLM_ENDPOINTS_B='[{"endpoint":"http://127.0.0.1:11434/v1","model":"gemma4:e4b","api_key":"","thinking":false,"output_token_parameter":"max_tokens"}]'
PHISHSHIELD_LLM_TEMPERATURE=0
PHISHSHIELD_LLM_SEED=42
```

每個端點陣列必須在 `.env` 中寫成**單行 JSON**。A／B 可以使用同一模型，也可各自指定模型與服務。模型 ID 精確比對，不自動補上 `:latest`。`output_token_parameter`指定服務接受的輸出上限欄位：Ollama 0.40.x使用`max_tokens`，預設則為`max_completion_tokens`；這不改變輸出上限數值，請依端點規格設定。

### 外部 API 與備援

將對應的端點改為服務提供的 HTTPS API base URL，填入模型 ID 與金鑰：

```dotenv
PHISHSHIELD_LLM_ENDPOINTS_A='[{"endpoint":"https://api.example.com/v1","model":"remote-model-id","api_key":"YOUR_API_KEY","thinking":null}]'
PHISHSHIELD_LLM_ENDPOINTS_B='[{"endpoint":"https://api.example.com/v1","model":"remote-model-id","api_key":"YOUR_API_KEY","thinking":null}]'
```

A／B 各可配置 **1–10 組**端點，按陣列順序備援。例如 A 先使用本機，服務暫時中斷時再嘗試外部服務：

```dotenv
PHISHSHIELD_LLM_ENDPOINTS_A='[{"endpoint":"http://127.0.0.1:11434/v1","model":"gemma4:e4b","api_key":"","thinking":false,"output_token_parameter":"max_tokens"},{"endpoint":"https://backup.example.com/v1","model":"remote-model-id","api_key":"YOUR_API_KEY","thinking":null}]'
```

端點支援自訂路徑。原生啟動允許 HTTPS，或 localhost／127.0.0.1／::1 的本機 HTTP；Compose 另明確允許容器使用 `host.docker.internal` 連到宿主機。其他區網明文 HTTP、內嵌帳密、query 與 fragment 不接受。`api_key` 留空時不會暗中取用 `OPENAI_API_KEY`；需要認證的服務應在相應端點填妥金鑰。

暫時斷線、建立連線逾時、連線容量不足及可恢復服務錯誤會有限重試，再按順序嘗試同階段的備援。預設每端點最多三次嘗試，包含首次，全部受總期限限制。讀取／寫入逾時、生成期限到達或來源不明的timeout會保留未完成結果，不再重做同一判斷或換模型重抽。認證／權限、輸出格式及證據支持驗證失敗亦停止。只有一組端點而連線失敗時，畫面會提示離線或未完成原因。

**選用遠端或遠端備援，即表示相應階段的資料可能送到該服務。** A 會收到郵件分析材料與原文證據；B 收到受控結構資料。若 A／B 使用同一供應商，B 的資料隔離不代表該供應商未取得 A 的原文。請妥善保管後端 `.env` 與金鑰。

### 思考模式與執行上限

| 每組端點的 `thinking` | 實際請求 |
|---|---|
| `false` | 傳送 `reasoning_effort=none`，請求關閉思考 |
| `true` | 傳送 `reasoning_effort=medium` |
| `null` | 不傳送該參數，沿用服務預設 |

實際效果取決於模型服務。若服務不支援 `reasoning_effort`，可明確設為 `null`；程式不會在錯誤後自行刪除參數重送。預設 `temperature=0`、`seed=42`；以 `PHISHSHIELD_LLM_SEED=null` 可不傳送 seed。低溫與固定 seed 減少變動，不保證跨服務或硬體完全重現，也不保證分類正確。

範本的執行上限如下，部署時以 `.env` 及程序環境為準：

| 設定 | 範本預設 |
|---|---|
| `PHISHSHIELD_LLM_CALL_TIMEOUT_SECONDS` | 單次模型呼叫 10 秒 |
| `PHISHSHIELD_LLM_TOTAL_TIMEOUT_SECONDS` | A／B 模型流程合計 30 秒 |
| `PHISHSHIELD_ANALYSIS_TIMEOUT_SECONDS` | 整體解析、模型、報告資料整理與保存 45 秒 |
| `PHISHSHIELD_LLM_MAX_OUTPUT_TOKENS_A` | A 每次最多 2,048 tokens |
| `PHISHSHIELD_LLM_MAX_OUTPUT_TOKENS_B` | B 每次最多 2,048 tokens |

A／B 上限各自設定，範圍為 1–16,384 tokens，所有同階段備援沿用該階段額度。未指定的階段回退至相容設定 `PHISHSHIELD_LLM_MAX_OUTPUT_TOKENS`（程式預設 2,048），兩種設定不是相加。範本直接列出 A／B，無須再填共用額度。輸出額度也納入該次 context 預留；放大 B 不會改變 A、輸入上限或分析總期限。

慢速本機模型可能需要調整期限與輸出上限。單封耗時受信件長度、模型速度及重試影響；提高上限不代表一定完成。其他重試與資源限制見 [.env.example](.env.example)。服務無法完成時會明示原因，不自動改用模擬結果。

## 結果怎麼看

「分類」描述信件風險；「模型分析」與「整體分析」描述本次處理是否完成，兩者分開閱讀。

| 工作台分類 | 代碼 | 意義 |
|---|---|---|
| 分析判定安全 | `SAFE` | 本次可分析內容符合安全分類條件，仍需考慮信件實際情境 |
| 需留意的訊號 | `SUSPICIOUS` | 有支持依據的可疑內容，應進一步確認 |
| 釣魚風險 | `PHISHING` | 有支持依據的釣魚風險，請核對理由與原文 |
| 交由人員判斷 | `UNKNOWN` | 目前未形成安全或釣魚結論 |

- **已完成＋交由人員判斷**：流程完成，但仍有資訊不足或不確定因素。
- **未完成＋交由人員判斷**：解析、模型、證據核對或服務等步驟未完成，需查看原因。
- **未啟用模型分析**：本次未進入模型階段，例如輸入未通過解析；不等於信件安全。

規則訊號是判讀參考，命中不直接等同釣魚。中文摘要、理由與建議由程式依已驗證的模型觀察及原文證據整理，畫面會標示說明來源；不代表已完成外部查證。「交由人員判斷」也不表示系統已有人工審批流程。


分析與保存狀態亦分開：有分析 ID 不代表已成功保存。若畫面提示未保存、保存未確認，或提交後連線中斷，請先查閱分析紀錄，再決定是否重送；重送會建立新分析。重新開啟歷史只讀取保存內容，不重新呼叫模型。

## API 與報告

API 前綴為 `/api/v1`，完整請求、回應及錯誤定義見 [API 使用說明](docs/project-api.md)。

| 用途 | 方法與路徑 |
|---|---|
| 服務與資料庫健康 | `GET /api/v1/health` |
| AI 連線／模型清單檢查 | `GET /api/v1/models/status` |
| 貼上文字規則預覽 | `POST /api/v1/rules` |
| 單封 EML／TXT 規則預覽 | `POST /api/v1/rules/file` |
| 貼上文字完整分析 | `POST /api/v1/analyses` |
| 單封 EML／TXT 完整分析 | `POST /api/v1/analyses/file` |
| 分頁／日期／關鍵字查詢 | `GET /api/v1/analyses` |
| 開啟單筆紀錄 | `GET /api/v1/analyses/{analysis_id}` |
| 單筆 PDF | `GET /api/v1/analyses/{analysis_id}/report.pdf` |
| 合併 PDF 或 ZIP | `POST /api/v1/reports/export` |

預覽文字：

```sh
curl -sS http://127.0.0.1:8000/api/v1/rules \
  -H 'Content-Type: application/json' \
  --data '{"text":"您好，本週會議紀錄已整理完成。"}'
```

提交完整分析：

```sh
curl -sS --max-time 310 http://127.0.0.1:8000/api/v1/analyses \
  -H 'Content-Type: application/json' \
  --data '{"text":"您好，本週會議紀錄已整理完成。","mode":"configured"}'
```

完整分析通常回 HTTP 201；服務未完成可能回 503，解析失敗可能回 422，超限可能回 413。請同時查看回覆中的完成與保存狀態。一般網站使用 `mode=configured`，API 的 `fake` 僅供明確啟用的測試程序。

單筆結果可直接「下載 PDF」。在分析紀錄勾選最多 20 筆後，可選擇「所有選取信件 → 一份 PDF」或「每封一份 PDF → ZIP 壓縮檔」；可跨頁勾選。匯出只讀取已保存結果，包含分類、理由、必要執行狀態及證據節錄，下載位置由瀏覽器管理。

## 資料保存與限制

- **資料在本機保存**：PostgreSQL 保存原始輸入的文字顯示、解碼正文、證據及分析結果；資料可能含個資。原始顯示文字不是郵件原始 bytes 的可逆備份。
- **閱讀方式**：網頁顯示文字，不執行信件腳本或載入其遠端圖片。HTML 採靜態抽取，與實際郵件軟體的 CSS 顯示可能不同。
- **分析範圍**：未實作真實 SPF／DKIM／DMARC、DNS／MX、網址訪問或信譽查詢；不分析附件內容，亦無 OCR 或圖片辨識。
- **判斷限制**：模型可能漏擷取、誤解或錯填內容；結構、引用及支持驗證通過，不保證語意真實或分類正確。B 無法重新閱讀原文補救 A 的遺漏。
- **部署範圍**：目前為本機工具，尚未提供多使用者認證、權限隔離或資料自動到期清除；公開部署、跨平台及辨識品質仍需個別驗收。

## 技術與產品目錄

| 技術 | 用途 |
|---|---|
| Python 3.12、FastAPI、Uvicorn | 後端 API、同站靜態頁面與 Swagger |
| 原生 HTML／CSS／JavaScript | 響應式工作台、批次佇列與報告操作 |
| Python email、Beautiful Soup、IDNA | MIME／HTML 文字及網址解析 |
| LangChain、OpenAI 相容 SDK | 結構化模型請求與 A／B 呼叫 |
| Pydantic | 設定與資料驗證 |
| SQLAlchemy asyncio、psycopg、PostgreSQL | 分析與原文保存、歷史查詢 |
| Alembic | 資料庫遷移 |
| ReportLab、內嵌中文字型 | PDF 與批次報告 |

| 路徑 | 內容 |
|---|---|
| `backend/app/` | 分析、API、資料庫與報告程式，含必要資源 |
| `backend/migrations/`、`backend/alembic.ini` | 資料庫遷移 |
| `frontend/` | 工作台與同站靜態資源 |
| `docs/` | API 使用文件 |
| `.env.example` | 本機／外部模型共用設定範本 |
| `Dockerfile`、`compose.yaml`、`docker/` | 應用映像、容器啟動與本機工作台／PostgreSQL |
| `requirements.txt`、`requirements.in` | 執行依賴與依賴範圍 |

安裝套件版本以 [requirements.txt](requirements.txt) 為準。

## 授權

本專案原創程式採用 [MIT License](LICENSE)。第三方素材保留各自授權：

- [Swagger UI](backend/app/api/docs_assets/NOTICE)：Apache-2.0。
- [Noto Sans TC](backend/app/assets/fonts/NotoSansTC-OFL.txt)、[Manrope](frontend/assets/fonts/OFL.txt)、[Caveat](frontend/assets/fonts/caveat-OFL.txt)：SIL Open Font License 1.1。
