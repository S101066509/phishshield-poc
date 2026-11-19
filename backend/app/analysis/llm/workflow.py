# 檔案功能：使用 LangChain LCEL 串接 A 擷取與驗證，再執行 B 判斷與驗證。

"""LCEL orchestration. Stage callbacks contain the application's validation policy."""

from langchain_core.runnables import RunnableLambda, RunnableSequence


def dual_stage_chain(extract, judge) -> RunnableSequence:
    # Validation in extract must succeed before judge is ever invoked.
    return RunnableLambda(extract, name="extract_and_validate_a") | RunnableLambda(
        judge, name="judge_and_validate_b"
    )
