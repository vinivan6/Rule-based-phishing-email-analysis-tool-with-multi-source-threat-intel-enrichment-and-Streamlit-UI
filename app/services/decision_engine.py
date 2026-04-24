from typing import Dict


def decide_final_outcome(
    rule_verdict: str,
    rule_confidence: str,
    reputation_overall: str,
    semantic_result: Dict,
) -> Dict:
    category = semantic_result.get("category", "uncertain")
    semantic_confidence = semantic_result.get("confidence", "low")

    final_verdict = rule_verdict
    final_confidence = rule_confidence
    final_action = "Treat with caution."

    # Strong scam families should win even without bad reputation
    if category == "extortion_blackmail":
        final_verdict = "phishing"
        final_confidence = "high"
        final_action = "Do not respond, pay, or engage. Preserve evidence and report the message."

    elif category in {"credential_phishing", "financial_scam", "job_scam", "helpdesk_support_scam"}:
        final_verdict = "phishing"
        if rule_confidence == "low":
            final_confidence = "medium"
        final_action = "Do not interact with links, attachments, requests, or sender instructions. Report the message."

    # Downgrade likely newsletters if structure looks bulk-mail-ish
    elif category == "newsletter_marketing":
        if rule_verdict == "phishing":
            final_verdict = "suspicious"
            final_confidence = "medium"
        elif rule_verdict == "suspicious":
            final_verdict = "likely_safe"
            final_confidence = "medium"
        else:
            final_verdict = "likely_safe"
            final_confidence = "medium"
        
        final_action = (
            "This appears more consistent with bulk or marketing email. "
            "Review before interacting, but it may be legitimate."
        )
    
    # Reputation can strengthen but should not blindly override newsletter logic
    if reputation_overall in {"malicious", "high_risk"} and category != "newsletter_marketing":
        final_verdict = "phishing"
        final_confidence = "high"
        final_action = "Known malicious or high-risk infrastructure was identified. Do not interact with the message."

    # If reputation is unavailable, keep semantic/rule decision
    if reputation_overall == "unavailable" and final_verdict == "suspicious":
        final_action = "Some external reputation checks were unavailable. Rely on the message analysis and proceed cautiously."

    if final_verdict == "likely_safe" and category == "uncertain":
        final_action = "No strong phishing indicators were detected. Review normally before interacting."

    if final_verdict == "phishing" and final_confidence == "high":
        final_action = "Do not interact with links, attachments, payment requests, or sender instructions. Verify through a trusted channel and report the message."

    return {
        "final_verdict": final_verdict,
        "final_confidence": final_confidence,
        "final_action": final_action,
        "semantic_category": category,
        "semantic_confidence": semantic_confidence,
    }