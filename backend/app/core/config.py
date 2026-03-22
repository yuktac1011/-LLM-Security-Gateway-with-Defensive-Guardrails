import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    # App Settings
    PROJECT_NAME: str = "The Identity Project"
    
    # LLM Settings
    # Defaulting to Groq/Llama3 for the free tier, but configurable
    LLM_API_KEY: str = os.getenv("LLM_API_KEY", "") 
    LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")
    MODEL_NAME: str = os.getenv("MODEL_NAME", "llama-3.3-70b-versatile") 
    
    # Pinecone Vector DB Settings
    PINECONE_API_KEY: str = os.getenv("PINECONE_API_KEY", "")
    PINECONE_INDEX_NAME: str = "security-cache"
    
    # Security Settings
    TRUSTED_SENDERS: list = ["mom@home.com", "boss@company.com"]

    class Config:
        case_sensitive = True

# Global instance to be used across the app
settings = Settings()