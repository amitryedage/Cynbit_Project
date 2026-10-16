"""
Security Advisory Relevance Matching Engine (Stage 2).
Reuses the Semantic Embedding and Lexical matching architecture to match incoming
threat advisories against client technology stack inventories and calculate contextual risk scores.
"""
from typing import List, Dict, Any, Optional
import re
from advisory_models import SecurityAdvisory, ClientProfile, ClientMatchResult, SAMPLE_CLIENTS
from embeddings import SemanticEmbedder

def normalize(text: str) -> str:
    return re.sub(r"[^\w\s]", " ", text.lower()).strip()

class AdvisoryMatcher:
    def __init__(self, embedder: Optional[SemanticEmbedder] = None):
        self.embedder = embedder or SemanticEmbedder()

    def match_asset_to_advisory(self, asset: Dict[str, Any], advisory: Dict[str, Any]) -> bool:
        """
        Determines whether a client asset is impacted by an advisory based on
        vendor, product name, and affected product lists.
        """
        adv_vendor = normalize(advisory.get("vendor", ""))
        adv_products = [normalize(p) for p in advisory.get("affected_products", [])]
        adv_text = normalize(f"{advisory.get('title', '')} {advisory.get('summary', '')} {advisory.get('technical_details', '')}")
        
        asset_vendor = normalize(asset.get("vendor", ""))
        asset_product = normalize(asset.get("product", ""))

        # 1. Vendor alignment check
        vendor_match = (asset_vendor in adv_vendor) or (adv_vendor in asset_vendor) or (asset_vendor in adv_text)
        if not vendor_match:
            return False

        # 2. Product name alignment check
        # Check if asset product appears in affected products or advisory text
        product_tokens = [tok for tok in asset_product.split() if len(tok) > 2]
        token_hits = sum(tok in adv_text or any(tok in p for p in adv_products) for tok in product_tokens)
        
        # Match if at least half of the product tokens match or exact substring matches
        if asset_product in adv_text or any(asset_product in p or p in asset_product for p in adv_products):
            return True
            
        return token_hits >= 1 and len(product_tokens) <= 2 or token_hits >= 2

    def evaluate_client(self, client: Dict[str, Any], advisory: Dict[str, Any]) -> ClientMatchResult:
        affected_assets = []
        highest_criticality = "low"

        for asset in client.get("tech_stack", []):
            if self.match_asset_to_advisory(asset, advisory):
                asset_label = f"{asset.get('vendor')} {asset.get('product')} (Installed: {asset.get('version', 'N/A')})"
                affected_assets.append(asset_label)
                if asset.get("criticality") == "critical":
                    highest_criticality = "critical"
                elif asset.get("criticality") == "high" and highest_criticality != "critical":
                    highest_criticality = "high"

        is_affected = len(affected_assets) > 0
        
        if not is_affected:
            return ClientMatchResult(
                client_id=client["client_id"],
                client_name=client["client_name"],
                is_affected=False,
                affected_assets=[],
                risk_score=0.0,
                urgency="Not Affected"
            )

        # Risk scoring algorithm
        cvss = float(advisory.get("cvss_score", 5.0))
        is_exploited = bool(advisory.get("is_actively_exploited", False))
        
        # Base score from CVSS
        risk = cvss * 0.70
        # Active in-the-wild exploitation premium
        if is_exploited:
            risk += 2.0
        # Asset criticality premium
        if highest_criticality == "critical":
            risk += 1.0
        elif highest_criticality == "high":
            risk += 0.5

        risk_score = round(min(risk, 10.0), 1)

        # Urgency assignment
        if risk_score >= 8.5:
            urgency = "Immediate Action (Emergency Window)"
        elif risk_score >= 6.5:
            urgency = "High Priority (Within 72 Hours)"
        else:
            urgency = "Standard Maintenance Window"

        return ClientMatchResult(
            client_id=client["client_id"],
            client_name=client["client_name"],
            is_affected=True,
            affected_assets=affected_assets,
            risk_score=risk_score,
            urgency=urgency
        )

    def match_advisory_across_all_clients(self, advisory: Dict[str, Any], clients: Optional[List[Dict[str, Any]]] = None) -> List[ClientMatchResult]:
        client_list = clients or SAMPLE_CLIENTS
        results = [self.evaluate_client(c, advisory) for c in client_list]
        # Sort so affected clients with highest risk appear first
        results.sort(key=lambda x: (x.is_affected, x.risk_score), reverse=True)
        return results
