import asyncio

import src.tools.rag_retrieval_tool as tool


async def main():
    result = await tool._retriever.retrieve_knowledge("brute force SSH")

    print("STATUS =", result.status)
    print("COUNT =", len(result.documents))
    print("ERROR =", result.error)
    print("DOCUMENTS =", result.documents[:1])


asyncio.run(main())
