"""
Steps 7-8 of the RAG pipeline — Build context, Preserve source references.
"""

from __future__ import annotations


def build_context(documents: list[dict]) -> str:
    """
    The LLM-prompt-ready text block: title, source, document type,
    relevance score, and relevant content per document — every field
    copied straight from the retrieved+ranked candidate, nothing invented.
    Returns an empty string (not a fabricated placeholder) when there are
    no documents to report.
    """
    if not documents:
        return ""

    sections = []
    for document in documents:
        metadata = document.get("metadata") or {}
        sections.append(
            "\n".join(
                [
                    f"Title: {document.get('title', '')}",
                    f"Source: {document.get('source', '')}",
                    f"Document Type: {metadata.get('documentType', '')}",
                    f"Relevance Score: {document.get('score', 0):.4f}",
                    "Content:",
                    document.get("content", ""),
                ]
            )
        )
    return "\n\n---\n\n".join(sections)


def build_sources(documents: list[dict]) -> list[dict]:
    """
    One entry per unique source document, deduplicated by documentId (a
    single document can contribute more than one retrieved chunk).
    Preserves the reference back to the original document exactly as
    stored (sourceUrl when available, else source:sourceId — see
    DocumentChunkMetadata.documentReference on the backend) — never
    inferred or guessed.
    """
    seen: set[str] = set()
    sources: list[dict] = []
    for document in documents:
        document_id = document.get("documentId")
        if not document_id or document_id in seen:
            continue
        seen.add(document_id)
        metadata = document.get("metadata") or {}
        sources.append(
            {
                "documentId": document_id,
                "title": document.get("title", ""),
                "source": document.get("source", ""),
                "documentReference": metadata.get("documentReference", ""),
            }
        )
    return sources
