"""RAG Document Ingestion Module for CodeSentinel.

Stores RAG-ready document objects produced by the AST Engine adapter (Step 5F)
into the persistent ChromaDB collection created in Step 6A.
Preserves all structural metadata while using upsert semantics for idempotency.
"""

import os
import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Sequence
from app.core.config import settings
from rag.vector_store import (
    get_collection,
    DEFAULT_COLLECTION_NAME,
    get_security_knowledge_collection,
    SECURITY_KNOWLEDGE_COLLECTION_NAME,
)

_CURATED_INGESTED_LOCK = threading.Lock()
_VERIFIED_KNOWLEDGE_PATHS: set = set()

MAX_DOC_CACHE_SIZE = 1024
_DOC_EMB_CACHE: "OrderedDict[str, List[float]]" = OrderedDict()
_DOC_EMB_LOCK = threading.Lock()


def reset_document_embedding_cache() -> None:
    """Reset the document embedding in-memory cache (for isolated tests)."""
    with _DOC_EMB_LOCK:
        _DOC_EMB_CACHE.clear()


def reset_curated_knowledge_cache() -> None:
    """Reset the verified curated knowledge in-memory cache (for isolated tests)."""
    with _CURATED_INGESTED_LOCK:
        _VERIFIED_KNOWLEDGE_PATHS.clear()


def _upsert_with_embedding_cache(
    collection: Any,
    ids: List[str],
    contents: List[str],
    metadatas: List[Dict[str, Any]],
) -> None:
    """Upsert documents into ChromaDB collection reusing cached embeddings when available."""
    embs: Optional[List[List[float]]] = None
    try:
        missing_indices: List[int] = []
        missing_contents: List[str] = []
        doc_embs: List[Optional[List[float]]] = [None] * len(contents)

        with _DOC_EMB_LOCK:
            for idx, content_str in enumerate(contents):
                if content_str in _DOC_EMB_CACHE:
                    _DOC_EMB_CACHE.move_to_end(content_str)
                    doc_embs[idx] = _DOC_EMB_CACHE[content_str]
                else:
                    missing_indices.append(idx)
                    missing_contents.append(content_str)

        if missing_contents and hasattr(collection, "_embedding_function") and collection._embedding_function:
            computed_missing = collection._embedding_function(missing_contents)
            if computed_missing is not None and len(computed_missing) == len(missing_contents):
                with _DOC_EMB_LOCK:
                    for idx, c_str, emb in zip(missing_indices, missing_contents, computed_missing):
                        emb_list = list(emb) if not isinstance(emb, list) else emb
                        _DOC_EMB_CACHE[c_str] = emb_list
                        if len(_DOC_EMB_CACHE) > MAX_DOC_CACHE_SIZE:
                            _DOC_EMB_CACHE.popitem(last=False)
                        doc_embs[idx] = emb_list

        if all(e is not None for e in doc_embs):
            embs = doc_embs  # type: ignore
    except Exception:
        embs = None

    if embs is not None:
        try:
            collection.upsert(
                ids=ids,
                documents=contents,
                metadatas=metadatas,
                embeddings=embs,
            )
            return
        except Exception:
            pass

    collection.upsert(
        ids=ids,
        documents=contents,
        metadatas=metadatas,
    )


def _clean_metadata_for_chroma(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Clean metadata dictionary to ensure compatibility with ChromaDB types.

    Converts None values to empty strings or suitable primitive defaults
    since ChromaDB requires str, int, float, or bool values in metadata dicts.
    """
    cleaned: Dict[str, Any] = {}
    for key, val in metadata.items():
        if val is None:
            cleaned[key] = ""
        elif isinstance(val, (str, int, float, bool)):
            cleaned[key] = val
        else:
            cleaned[key] = str(val)
    return cleaned


def ingest_documents(
    documents: List[Dict[str, Any]],
    collection_name: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Ingest a list of RAG document objects into the persistent ChromaDB vector store.

    Parameters:
      documents: List of document dicts, each with 'document_id', 'content', and 'metadata'.
      collection_name: Optional custom collection name; defaults to DEFAULT_COLLECTION_NAME.
      db_path: Optional database storage path override.

    Returns:
      Summary dict containing status, ingested_count, and collection_name.
    """
    target_coll_name = collection_name or DEFAULT_COLLECTION_NAME

    if not documents:
        return {
            "status": "success",
            "ingested_count": 0,
            "collection_name": target_coll_name,
        }

    ids: List[str] = []
    contents: List[str] = []
    metadatas: List[Dict[str, Any]] = []

    for doc in documents:
        doc_id = doc.get("document_id")
        content = doc.get("content", "")
        meta = doc.get("metadata", {})

        if doc_id and content:
            ids.append(str(doc_id))
            contents.append(str(content))
            metadatas.append(_clean_metadata_for_chroma(meta))

    if not ids:
        return {
            "status": "success",
            "ingested_count": 0,
            "collection_name": target_coll_name,
        }

    collection = get_collection(collection_name=target_coll_name, db_path=db_path)

    # Use upsert with embedding cache to guarantee idempotency and avoid duplicate ID errors
    _upsert_with_embedding_cache(
        collection=collection,
        ids=ids,
        contents=contents,
        metadatas=metadatas,
    )

    return {
        "status": "success",
        "ingested_count": len(ids),
        "collection_name": target_coll_name,
    }


def ingest_security_knowledge(
    documents: List[Dict[str, Any]],
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Ingest general security knowledge documents into the dedicated ChromaDB collection.

    Flow:
      Security Knowledge Documents
              ↓
      load_security_knowledge()
              ↓
      chunk_security_knowledge()
              ↓
      codesentinel_security_knowledge

    Parameters:
      documents: List of raw security document dicts.
      db_path: Optional database storage path override.

    Returns:
      Dict with status, ingested_count (number of chunks ingested), and collection_name.
    """
    from knowledge.loader import load_security_knowledge, chunk_security_knowledge

    target_coll_name = SECURITY_KNOWLEDGE_COLLECTION_NAME

    if not documents or not isinstance(documents, list):
        return {
            "status": "success",
            "ingested_count": 0,
            "collection_name": target_coll_name,
        }

    # Step 1: Load and validate documents
    validated_docs = load_security_knowledge(documents)

    if not validated_docs:
        return {
            "status": "success",
            "ingested_count": 0,
            "collection_name": target_coll_name,
        }

    # Step 2: Chunk each validated document
    all_chunks: List[Dict[str, Any]] = []
    for doc in validated_docs:
        doc_chunks = chunk_security_knowledge(doc)
        all_chunks.extend(doc_chunks)

    if not all_chunks:
        return {
            "status": "success",
            "ingested_count": 0,
            "collection_name": target_coll_name,
        }

    # Step 3: Prepare vectors for ChromaDB upsert
    ids: List[str] = []
    contents: List[str] = []
    metadatas: List[Dict[str, Any]] = []

    for chunk in all_chunks:
        chunk_id = chunk.get("document_id")
        content = chunk.get("content", "")
        meta = chunk.get("metadata", {})

        if chunk_id and content:
            ids.append(str(chunk_id))
            contents.append(str(content))
            metadatas.append(_clean_metadata_for_chroma(meta))

    if not ids:
        return {
            "status": "success",
            "ingested_count": 0,
            "collection_name": target_coll_name,
        }

    # Step 4: Upsert into codesentinel_security_knowledge collection
    collection = get_security_knowledge_collection(db_path=db_path)
    _upsert_with_embedding_cache(
        collection=collection,
        ids=ids,
        contents=contents,
        metadatas=metadatas,
    )

    return {
        "status": "success",
        "ingested_count": len(ids),
        "collection_name": target_coll_name,
    }


def ensure_curated_knowledge_ingested(
    db_path: Optional[str] = None,
    force: bool = False,
    include_external: Optional[bool] = None,
) -> Dict[str, Any]:
    """Ensure that the 12 curated OWASP/CWE knowledge documents are ingested into ChromaDB.

    Checks the dedicated security knowledge collection. If the curated catalog is already present
    and force is False, returns existing status without redundant disk writes.
    If missing or force is True, ingests CURATED_OWASP_KNOWLEDGE deterministically and idempotently.

    Thread-safe and process-cached by normalized database path.

    Parameters:
      db_path: Optional database storage path override.
      force: If True, re-upserts all documents regardless of current collection state.
      include_external: If True, also ingests external knowledge (MITRE CWE, CISA KEV).
        If None, reads from settings.ENABLE_EXTERNAL_KNOWLEDGE (default False).

    Returns:
      Dict with status, ingested_count, and collection_name.
    """
    from knowledge.curated_owasp import CURATED_OWASP_KNOWLEDGE

    target_path = os.path.normcase(os.path.abspath(db_path or settings.CHROMA_DB_PATH))

    if not force:
        with _CURATED_INGESTED_LOCK:
            if target_path in _VERIFIED_KNOWLEDGE_PATHS:
                res = {
                    "status": "success",
                    "ingested_count": 0,
                    "collection_name": SECURITY_KNOWLEDGE_COLLECTION_NAME,
                    "already_present": True,
                }
                # Check opt-in external ingestion even if core is cached
                should_ingest_ext = include_external if include_external is not None else getattr(settings, "ENABLE_EXTERNAL_KNOWLEDGE", False)
                if should_ingest_ext:
                    ext_res = ingest_external_security_knowledge(db_path=db_path, force=force)
                    res["external_knowledge"] = ext_res
                return res

    collection = get_security_knowledge_collection(db_path=db_path)
    canonical_sample_chunk_id = "knowledge_cwe_89_sql_injection_chunk_1"

    if not force and collection.count() > 0:
        try:
            existing = collection.get(ids=[canonical_sample_chunk_id])
            if existing and existing.get("ids"):
                with _CURATED_INGESTED_LOCK:
                    _VERIFIED_KNOWLEDGE_PATHS.add(target_path)
                res = {
                    "status": "success",
                    "ingested_count": 0,
                    "collection_name": SECURITY_KNOWLEDGE_COLLECTION_NAME,
                    "already_present": True,
                }
                should_ingest_ext = include_external if include_external is not None else getattr(settings, "ENABLE_EXTERNAL_KNOWLEDGE", False)
                if should_ingest_ext:
                    ext_res = ingest_external_security_knowledge(db_path=db_path, force=force)
                    res["external_knowledge"] = ext_res
                return res
        except Exception:
            pass

    res = ingest_security_knowledge(CURATED_OWASP_KNOWLEDGE, db_path=db_path)
    if isinstance(res, dict) and res.get("status") == "success":
        with _CURATED_INGESTED_LOCK:
            _VERIFIED_KNOWLEDGE_PATHS.add(target_path)

    # Opt-in external knowledge ingestion
    should_ingest_ext = include_external if include_external is not None else getattr(settings, "ENABLE_EXTERNAL_KNOWLEDGE", False)
    if should_ingest_ext:
        ext_res = ingest_external_security_knowledge(db_path=db_path, force=force)
        res["external_knowledge"] = ext_res

    return res


# ---------------------------------------------------------------------------
# External Security Knowledge Ingestion (Upgrade 2A-4 Opt-In)
# ---------------------------------------------------------------------------

ALLOWED_EXTERNAL_SOURCES: Sequence[str] = ("mitre_cwe", "cisa_kev")
EXTERNAL_INGESTION_BATCH_SIZE: int = 50


def ingest_external_security_knowledge(
    sources: Optional[Sequence[str]] = None,
    db_path: Optional[str] = None,
    force: bool = False,
    dataset_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Ingest curated external security knowledge (MITRE CWE and CISA KEV) into ChromaDB.

    Enforces:
    1. Scope: Only 'mitre_cwe' and 'cisa_kev' are allowed in production.
       CVEfixes is explicitly blocked pending a standalone authentic slice.
    2. Idempotency: Uses deterministic chunk IDs and sample chunk existence checks.
    3. Bounded Batching: Upserts in bounded batches of 50 chunks.
    4. Safe Invariants: metadata['severity'] is None, max 4,000 chars per doc.
    5. Advisory-Only: External docs populate codesentinel_security_knowledge without
       altering deterministic findings or security-gate decisions.

    Parameters:
      sources: Sequence of source names (default: ['mitre_cwe', 'cisa_kev']).
      db_path: Optional ChromaDB storage path override.
      force: If True, re-upserts chunks even if already present.
      dataset_dir: Optional override for the root datasets directory.

    Returns:
      Summary dict containing per-source metrics, document counts, chunk counts, and status.
    """
    from knowledge.loader import load_security_knowledge, chunk_security_knowledge
    from knowledge.curation import MitreCweCurator, CisaKevCurator

    requested_sources = list(sources) if sources is not None else list(ALLOWED_EXTERNAL_SOURCES)

    # Validate requested sources
    for src in requested_sources:
        if str(src).lower() == "cvefixes":
            raise ValueError(
                "CVEfixes dataset is blocked from production ingestion: "
                "12.7 GB raw archive cannot be extracted safely in production/CI."
            )
        if str(src).lower() not in ALLOWED_EXTERNAL_SOURCES:
            raise ValueError(
                f"Invalid external knowledge source '{src}'. "
                f"Allowed sources: {list(ALLOWED_EXTERNAL_SOURCES)}"
            )

    root_datasets = dataset_dir or os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "datasets")
    )

    collection = get_security_knowledge_collection(db_path=db_path)
    source_results: Dict[str, Any] = {}
    total_docs = 0
    total_chunks = 0

    for src in requested_sources:
        src_lower = src.lower()
        if src_lower == "mitre_cwe":
            zip_path = os.path.join(root_datasets, "mitre_cwe", "cwec_latest.xml.zip")
            if not os.path.isfile(zip_path):
                raise FileNotFoundError(f"MITRE CWE archive not found at: {zip_path}")

            sample_chunk_id = "knowledge_mitre_cwe_CWE-89_chunk_1"
            if not force and collection.count() > 0:
                try:
                    existing = collection.get(ids=[sample_chunk_id])
                    if existing and existing.get("ids"):
                        source_results["mitre_cwe"] = {
                            "status": "success",
                            "document_count": 26,
                            "chunk_count": 0,
                            "already_present": True,
                        }
                        total_docs += 26
                        continue
                except Exception:
                    pass

            curator = MitreCweCurator()
            curated_docs = curator.curate_from_zip(zip_path)
            raw_docs = [d.to_dict() for d in curated_docs]
            validated_docs = load_security_knowledge(raw_docs)

            chunks: List[Dict[str, Any]] = []
            for d in validated_docs:
                chunks.extend(chunk_security_knowledge(d))

            chunk_ids = [str(c["document_id"]) for c in chunks if c.get("document_id") and c.get("content")]
            chunk_contents = [str(c["content"]) for c in chunks if c.get("document_id") and c.get("content")]
            chunk_metas = [_clean_metadata_for_chroma(c.get("metadata", {})) for c in chunks if c.get("document_id") and c.get("content")]

            # Bounded batching: 50 chunks per upsert batch
            for i in range(0, len(chunk_ids), EXTERNAL_INGESTION_BATCH_SIZE):
                _upsert_with_embedding_cache(
                    collection=collection,
                    ids=chunk_ids[i : i + EXTERNAL_INGESTION_BATCH_SIZE],
                    contents=chunk_contents[i : i + EXTERNAL_INGESTION_BATCH_SIZE],
                    metadatas=chunk_metas[i : i + EXTERNAL_INGESTION_BATCH_SIZE],
                )

            source_results["mitre_cwe"] = {
                "status": "success",
                "document_count": len(curated_docs),
                "chunk_count": len(chunk_ids),
                "already_present": False,
            }
            total_docs += len(curated_docs)
            total_chunks += len(chunk_ids)

        elif src_lower == "cisa_kev":
            csv_path = os.path.join(root_datasets, "cisa_kev", "known_exploited_vulnerabilities.csv")
            if not os.path.isfile(csv_path):
                raise FileNotFoundError(f"CISA KEV CSV not found at: {csv_path}")

            sample_chunk_id = "knowledge_cisa_kev_CVE-2024-21413_chunk_1"
            if not force and collection.count() > 0:
                try:
                    existing = collection.get(ids=[sample_chunk_id])
                    if existing and existing.get("ids"):
                        source_results["cisa_kev"] = {
                            "status": "success",
                            "document_count": 429,
                            "chunk_count": 0,
                            "already_present": True,
                        }
                        total_docs += 429
                        continue
                except Exception:
                    pass

            curator_kev = CisaKevCurator()
            curated_docs_kev, stats = curator_kev.curate_from_file(csv_path)
            raw_docs_kev = [d.to_dict() for d in curated_docs_kev]
            validated_docs_kev = load_security_knowledge(raw_docs_kev)

            chunks_kev: List[Dict[str, Any]] = []
            for d in validated_docs_kev:
                chunks_kev.extend(chunk_security_knowledge(d))

            chunk_ids_kev = [str(c["document_id"]) for c in chunks_kev if c.get("document_id") and c.get("content")]
            chunk_contents_kev = [str(c["content"]) for c in chunks_kev if c.get("document_id") and c.get("content")]
            chunk_metas_kev = [_clean_metadata_for_chroma(c.get("metadata", {})) for c in chunks_kev if c.get("document_id") and c.get("content")]

            # Bounded batching: 50 chunks per upsert batch
            for i in range(0, len(chunk_ids_kev), EXTERNAL_INGESTION_BATCH_SIZE):
                _upsert_with_embedding_cache(
                    collection=collection,
                    ids=chunk_ids_kev[i : i + EXTERNAL_INGESTION_BATCH_SIZE],
                    contents=chunk_contents_kev[i : i + EXTERNAL_INGESTION_BATCH_SIZE],
                    metadatas=chunk_metas_kev[i : i + EXTERNAL_INGESTION_BATCH_SIZE],
                )

            source_results["cisa_kev"] = {
                "status": "success",
                "document_count": len(curated_docs_kev),
                "chunk_count": len(chunk_ids_kev),
                "already_present": False,
                "stats": {
                    "source_records": stats.total_source_records,
                    "missing_cwe": stats.missing_cwe_records,
                    "unsupported_cwe": stats.unsupported_cwe_records,
                    "matched_associations": stats.matched_cwe_associations,
                },
            }
            total_docs += len(curated_docs_kev)
            total_chunks += len(chunk_ids_kev)

    return {
        "status": "success",
        "sources": source_results,
        "total_documents": total_docs,
        "total_chunks": total_chunks,
        "collection_name": SECURITY_KNOWLEDGE_COLLECTION_NAME,
    }



