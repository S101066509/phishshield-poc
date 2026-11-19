# 檔案功能：匯出最終決策入口，供命令列與應用服務取得完整分析結果。

from app.analysis.decision.engine import finalize_analysis

__all__ = ["finalize_analysis"]
