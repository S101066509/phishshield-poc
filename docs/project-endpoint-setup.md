# AI 端點連接教學

本教學適用於 PhishShield 1.0.0 概念驗證（PoC）。本機 Ollama、外部 API 與 Docker 部署都使用**專案根目錄同一份 `.env`**。A 負責讀信與擷取觀察，B 負責依受控資料判讀；兩階段都需要有效端點，可共用同一模型與服務。

## 1. 準備設定檔

在專案根目錄執行；已有 `.env` 時直接編輯原檔：

```sh
cp -n .env.example .env
```

下列每個 `PHISHSHIELD_LLM_ENDPOINTS_*` 都要在 `.env` 寫成**單行 JSON 陣列**，不要加 `export`。不要公開或上傳含實際金鑰的檔案。

| 欄位 | 填寫方式 |
|---|---|
| `endpoint` | OpenAI 相容 API 的基底網址，例如 `http://127.0.0.1:11434/v1`；不用加 `/chat/completions` 或 `/models` |
| `model` | 服務提供的完整模型 ID，須精確匹配，不自動補 `:latest` |
| `api_key` | 原始金鑰，不加`Bearer `前綴；本機服務不需要認證時可留空 |
| `thinking` | `false`請求關閉思考、`true`請求中等思考、`null`沿用服務預設 |

服務除了 Chat Completions，還須支援本系統使用的嚴格 JSON Schema 輸出。請依下列本機或外部服務範例設定。

## 2A. 連接本機 Ollama

先確認主機上的 Ollama 已啟動，並列出已安裝模型：

```sh
ollama list
curl -sS http://127.0.0.1:11434/v1/models
```

若 Ollama 尚未執行，在另一個終端機執行 `ollama serve`；已有背景服務時不必重複啟動。以下使用 `gemma4:e4b` 作範例，請填入自己的實際模型 ID：

```dotenv
PHISHSHIELD_LLM_ENDPOINTS_A='[{"endpoint":"http://127.0.0.1:11434/v1","model":"gemma4:e4b","api_key":"","thinking":false}]'
PHISHSHIELD_LLM_ENDPOINTS_B='[{"endpoint":"http://127.0.0.1:11434/v1","model":"gemma4:e4b","api_key":"","thinking":false}]'
PHISHSHIELD_LLM_TEMPERATURE=0
PHISHSHIELD_LLM_SEED=42
```

Compose 不會替你安裝模型權重或啟動 Ollama。容器啟動時會將上述 HTTP loopback 位址轉為 `host.docker.internal`，只改容器程序中的設定，原 `.env` 不改寫。原生 Python 啟動則直接使用原 loopback 位址。

**主機可連到 Ollama，不代表容器一定可連到。** Docker Desktop需能從容器存取主機服務；Linux Docker Engine的host-gateway路由與Ollama監聽位址亦須相符。若後續顯示offline，先檢查這條容器到主機的連線，不要把模型位址改成Compose的PostgreSQL服務名。

## 2B. 連接外部 OpenAI 相容 API

把服務商提供的 **HTTPS API base URL、模型 ID及金鑰**填入對應位置：

```dotenv
PHISHSHIELD_LLM_ENDPOINTS_A='[{"endpoint":"https://api.example.com/v1","model":"remote-model-id","api_key":"YOUR_API_KEY","thinking":null}]'
PHISHSHIELD_LLM_ENDPOINTS_B='[{"endpoint":"https://api.example.com/v1","model":"remote-model-id","api_key":"YOUR_API_KEY","thinking":null}]'
```

以上網域與金鑰是佔位範例，不能直接用來連線。服務若使用其他base path，依其文件完整填寫。A／B可用不同服務、模型或金鑰。程式不會隱含使用`OPENAI_API_KEY`；需要認證時請在各端點的`api_key`填妥。

`thinking=null`會省略`reasoning_effort`；`false`與`true`分別傳送`none`與`medium`。服務不支援該參數時可明確設為`null`，但仍須支援程式送出的其他採樣參數及結構化輸出；不會在錯誤後偷偷刪除參數重送。

**選用遠端服務即表示相應資料會送到該服務。** A收到郵件分析材料，B收到受控結構資料；請只提交可送往該服務的內容。

### 多端點備援

每階段可設1–10組，依陣列順序嘗試。例如A先用本機，再用外部備援：

```dotenv
PHISHSHIELD_LLM_ENDPOINTS_A='[{"endpoint":"http://127.0.0.1:11434/v1","model":"gemma4:e4b","api_key":"","thinking":false},{"endpoint":"https://backup.example.com/v1","model":"remote-model-id","api_key":"YOUR_API_KEY","thinking":null}]'
```

B需獨立設定自己的陣列。暫時斷線、逾時及可恢復服務錯誤才會有限重試／備援；認證、輸出格式、引用或支持驗證失敗不會透過換端點重新抽答案。全部嘗試共用期限，不是每組端點各自取得完整期限。

## 3. 套用設定

首次啟動，或尚未建置映像時：

```sh
docker compose up -d --build
```

只修改`.env`後，重新建立應用容器，讓Compose重新載入環境：

```sh
docker compose up -d --force-recreate app
```

單純`docker compose restart app`不會重新載入已變更的Compose環境設定。原生Python啟動時則重新啟動後端程序即可；無須source設定檔。同名程序環境變數優先於檔案設定，請留意舊終端機中的覆寫。

## 4. 檢查連接結果

開啟工作台的「重新檢查連線」，或執行：

```sh
curl -sS http://127.0.0.1:8000/api/v1/health
curl -sS http://127.0.0.1:8000/api/v1/models/status
```

第一個端點檢查應用與資料庫；第二個才檢查AI端點。模型檢查只讀取各API base後的`/models`，不送信、不推論，也不保存紀錄。

| 狀態 | 如何理解 |
|---|---|
| `configuration_valid=true` | 端點與模型設定通過本地格式檢查；不表示金鑰或推論已驗證 |
| `connected=true` | A與B均能從服務清單找到精確匹配的模型ID，可能使用各自備援 |
| `availability=missing` | 模型清單可讀，但設定的ID未找到；核對完整名稱 |
| `availability=offline` | 目前有階段無法連到服務，檢查位址、服務與網路 |
| `availability=unconfirmed` | 清單不支援、回覆不符或尚未確認；不能直接等同推論不可用 |
| `service_reachable=true` | 至少收到HTTP回覆；401／403等認證失敗也可能為true |

`stages.a`與`stages.b`分開列出端點數、逐端點原因及第一個可用索引。清單檢查總期限4秒；逾時可能只留下已檢查部分，請一併讀`reason_code`。檢查成功不保證下一次推論成功，也不代表服務已通過嚴格Schema驗收。

可用索引只代表這次清單檢查，沒有永久切換推論路由；完整分析仍從設定陣列的第一組開始。

確認後可貼上一段**合成測試文字**，按「開始分析」，再查看模型是否完成與未完成原因。這一步會實際呼叫配置的模型並保存結果；不要用真實郵件作第一次連通測試。分析沒有完成時，依具體原因處理，不能把UNKNOWN當成安全。

## 常見問題

| 現象／原因碼 | 檢查方式 |
|---|---|
| `LLM_NOT_CONFIGURED`／`LLM_CONFIGURATION_INVALID` | A及B是否都填寫、JSON是否為單行合法陣列、endpoint／model是否留空、修改後是否重建app |
| `MODEL_STATUS_AUTH_FAILED` | 核對該端點金鑰及權限；service_reachable=true不代表認證成功 |
| `MODEL_STATUS_MODEL_MISSING` | 使用服務實際列出的完整ID，不靠簡稱或自動補標籤 |
| `MODEL_STATUS_UNSUPPORTED` | 服務可能不提供`/models`；確認base URL及服務文件，狀態保持未確認 |
| `MODEL_STATUS_OFFLINE`／`MODEL_STATUS_TIMEOUT` | 確認服務已啟動、容器到主機可達及路徑正確；清單檢查與完整推論的期限不同 |
| 清單成功，但分析輸出或證據無效 | 連通性已成立，仍需核對模型的結構化輸出及分析能力；不是改Key就能解決 |
| 修改設定後仍使用舊值 | Compose需force-recreate；原生需重啟程序，並檢查程序環境變數覆寫 |

完整使用方式見[README](../README.md)，回應欄位與API範例見[API說明](project-api.md)，其他執行上限見[環境範本](../.env.example)。
