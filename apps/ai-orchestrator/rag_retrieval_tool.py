if document_type == "PLAYBOOK":
    result = await _retriever.retrieve_playbooks(
        query,
        filters=filters,
    )
else:
    result = await _retriever.retrieve_knowledge(
        query,
        filters=filters,
    )
