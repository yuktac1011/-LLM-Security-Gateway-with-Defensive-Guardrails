import hashlib
from pinecone import Pinecone
from openai import AsyncOpenAI
from app.core.config import settings

# Initialize Pinecone Client
pc = Pinecone(api_key=settings.PINECONE_API_KEY)
index = pc.Index(settings.PINECONE_INDEX_NAME)

# We use standard OpenAI API for embeddings (or your preferred provider)
client = AsyncOpenAI(api_key=settings.LLM_API_KEY) # Using standard OpenAI for embeddings

async def get_embedding(text: str) -> list[float]:
    """Converts text into a 1536-dimensional mathematical vector."""
    try:
        response = await client.embeddings.create(
            input=text,
            model="text-embedding-3-small" # Industry standard fast embedding model
        )
        return response.data[0].embedding
    except Exception as e:
        print(f"Embedding failed: {e}")
        return []

async def check_semantic_cache(text: str) -> dict | None:
    """
    Queries Pinecone to see if this exact semantic intent has been flagged before.
    Returns the cached ML Report if Cosine Similarity > 95%.
    """
    embedding = await get_embedding(text)
    if not embedding:
        return None
        
    try:
        # Search the Vector DB for the 1 closest match
        results = index.query(
            vector=embedding,
            top_k=1,
            include_metadata=True
        )
        
        if results.matches and results.matches[0].score > 0.95:
            metadata = results.matches[0].metadata
            if metadata.get("is_malicious"):
                return {
                    "is_malicious": True,
                    "confidence_score": metadata.get("confidence_score", 0.99),
                    "threat_type": metadata.get("threat_type", "Cached Threat"),
                    "reasoning": f"Semantic Cache Hit (Similarity: {results.matches[0].score:.2f}). {metadata.get('reasoning', '')}"
                }
    except Exception as e:
        print(f"Pinecone query failed: {e}")
        
    return None

def save_to_semantic_cache(text: str, ml_report: dict, embedding: list[float]):
    """
    Saves a newly discovered attack to Pinecone so it's blocked instantly next time.
    """
    try:
        # Create a unique ID based on the text hash
        text_id = hashlib.sha256(text.encode()).hexdigest()
        
        index.upsert(
            vectors=[{
                "id": text_id,
                "values": embedding,
                "metadata": {
                    "is_malicious": ml_report.get("is_malicious", False),
                    "confidence_score": ml_report.get("confidence_score", 0.0),
                    "threat_type": ml_report.get("threat_type", "Unknown"),
                    "reasoning": ml_report.get("reasoning", "")
                }
            }]
        )
    except Exception as e:
        print(f"Pinecone upsert failed: {e}")