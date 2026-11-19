# 檔案功能：公開受控雙模型管線；原文比較流程僅由明確的工程評估入口使用。
from app.analysis.llm.event_pipeline import EventDualLLMPipeline
from app.analysis.llm.isolated_pipeline import IsolatedDualLLMPipeline
from app.analysis.llm.pipeline import configured_pipeline

DualLLMPipeline = IsolatedDualLLMPipeline

__all__ = [
    "DualLLMPipeline",
    "EventDualLLMPipeline",
    "IsolatedDualLLMPipeline",
    "configured_pipeline",
]
