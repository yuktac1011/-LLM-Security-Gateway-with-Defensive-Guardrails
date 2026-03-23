import uuid
from pinecone import Pinecone
from app.core.config import settings

# Initialize Pinecone Client
pc = Pinecone(api_key=settings.PINECONE_API_KEY)
index = pc.Index(settings.PINECONE_INDEX_NAME)

# Pinecone's built-in embedding model (1024 dimensions)
EMBEDDING_MODEL = "multilingual-e5-large" 

async def check_semantic_cache(text: str) -> dict | None:
    """
    Searches Pinecone to see if a mathematically similar attack has been caught before.
    Returns the cached ML report if found, else returns None.
    """
    try:
        # 1. Convert user text to a Vector Embedding
        embedding = pc.inference.embed(
            model=EMBEDDING_MODEL,
            inputs=[text],
            parameters={"input_type": "query"}
        )
        vector_math = embedding[0].values
        
        # 2. Search Pinecone for similar attacks (Cosine Similarity)
        results = index.query(
            vector=vector_math,
            top_k=1,
            include_metadata=True
        )
        
        # 3. Check Confidence Score of the similarity match
        if results.matches and results.matches[0].score > 0.90:
            metadata = results.matches[0].metadata
            return {
                "is_malicious": True,
                "confidence_score": 0.99,
                "threat_type": metadata.get("threat_type", "Cached Threat"),
                "reasoning": f"Blocked by Pinecone Semantic Cache. Similarity match: {round(results.matches[0].score * 100, 1)}%"
            }
        return None
    except Exception as e:
        print(f"Pinecone Cache Search Error: {e}")
        return None

async def add_to_semantic_cache(text: str, ml_report: dict):
    """
    AUTO-LEARNING: Saves new, verified attacks to the Vector DB.
    """
    try:
        # 1. Convert the malicious text to a vector
        embedding = pc.inference.embed(
            model=EMBEDDING_MODEL,
            inputs=[text],
            parameters={"input_type": "passage"}
        )
        vector_math = embedding[0].values
        
        # 2. Save it to Pinecone with the ML Report as Metadata
        index.upsert(
            vectors=[{
                "id": str(uuid.uuid4()), 
                "values": vector_math, 
                "metadata": {
                    "threat_type": ml_report.get("threat_type", "Unknown"),
                    "original_text": text[:200]
                }
            }]
        )
        print("Successfully learned and cached new threat vector in Pinecone.")
    except Exception as e:
        print(f"Pinecone Upsert Error: {e}")