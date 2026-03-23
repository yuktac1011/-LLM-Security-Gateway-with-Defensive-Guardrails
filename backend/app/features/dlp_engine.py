from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

class DLPEngine:
    def __init__(self):
        # Load the engines once for high performance
        self.analyzer = AnalyzerEngine(default_score_threshold=0.4)
        self.anonymizer = AnonymizerEngine()
        
        # Define which PII types we want to redact
        self.target_entities = [
            "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD", 
            "LOCATION", "PERSON", "US_SSN", "IP_ADDRESS"
        ]

    def redact_pii(self, text: str) -> str:
        """
        Scans text and redacts sensitive information.
        Maintains structural integrity of the email for summarization.
        """
        if not text:
            return text

        # 1. Analyze the text for PII
        results = self.analyzer.analyze(
            text=text, 
            entities=self.target_entities, 
            language='en'
        )

        # 2. Define how to redact (replace with [REDACTED_TYPE])
        operators = {
            entity: OperatorConfig("replace", {"new_value": f"[{entity}]"})
            for entity in self.target_entities
        }

        # 3. Execute Anonymization
        anonymized_result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators
        )

        return anonymized_result.text

# Global instance for thread-safe concurrent access
dlp_manager = DLPEngine()