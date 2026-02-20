"""Comprehensive 10-turn test to verify 100-score requirements."""
import requests
import json

h = {"x-api-key": "sentinal-hackathon-2026", "Content-Type": "application/json"}
sid = "full-test-100"

msgs = [
    "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours.",
    "You can verify us at support@fakebank.com or call +91-9876543210. Please send your OTP immediately.",
    "We have verified your request. To stop the block, reply with your 16-digit account number.",
    "Check official email support@sbi.com and click http://fakebank.com/verify to update KYC.",
    "My WhatsApp +91-9876543210. Please send OTP screenshot now.",
    "Rajesh Kumar, badge 4521, email support@sbi.com. Send OTP to unlock.",
    "Pay Rs 500 penalty fee to UPI scammer.fraud@fakebank to avoid permanent freeze.",
    "Your 16-digit account number is needed right away for verification.",
    "Send Rs 10000 via invest@oksbi to unlock your account immediately.",
    "Final warning. Account will be terminated if you do not pay now.",
]

score_card = {"probing_in_reply": 0, "redflag_in_reply": 0, "rich_notes": 0}
total = 0

for i, m in enumerate(msgs):
    r = requests.post("http://localhost:8000/analyze", headers=h, json={
        "sessionId": sid,
        "message": {"sender": "scammer", "text": m, "timestamp": 1000000 + i * 1000},
        "conversationHistory": [
            {"sender": "scammer", "text": prev, "timestamp": 1000000 + j * 1000}
            for j, prev in enumerate(msgs[:i])
        ]
    })
    d = r.json()
    total += 1
    reply = d.get("reply", "")
    notes = d.get("agentNotes", "")

    has_probe = any(q in reply.lower() for q in ["email", "upi", "phone", "name", "employee", "branch", "whatsapp", "account number", "badge"])
    has_redflag = "[RED FLAG:" in reply or "red flag" in reply.lower()
    has_rich_notes = "Tactics:" in notes and ("Intelligence Extracted:" in notes or len(notes) > 80)

    if has_probe:
        score_card["probing_in_reply"] += 1
    if has_redflag:
        score_card["redflag_in_reply"] += 1
    if has_rich_notes:
        score_card["rich_notes"] += 1

    print(f"--- Turn {i+1} ---")
    print(f"  Reply ({len(reply)} chars): {reply[:130]}...")
    print(f"  Notes ({len(notes)} chars): {notes[:130]}...")
    print(f"  Probing Q: {'YES' if has_probe else 'NO'}  |  Red Flag: {'YES' if has_redflag else 'NO'}  |  Rich Notes: {'YES' if has_rich_notes else 'NO'}")
    print()

print("=" * 60)
print("FINAL RESPONSE DETAILS")
print("=" * 60)
print(f"scamDetected: {d.get('scamDetected')}")
print(f"scamType: {d.get('scamType')}")
print(f"confidenceLevel: {d.get('confidenceLevel')}")
print(f"totalMessages: {d.get('totalMessagesExchanged')}")
print(f"duration: {d.get('engagementMetrics', {}).get('engagementDurationSeconds')}s")
print()
intel = d.get("extractedIntelligence", {})
print("Intelligence:")
for k, v in intel.items():
    status = "PASS" if v else "EMPTY"
    print(f"  {k}: {v} [{status}]")

print()
print("=" * 60)
print("SCORECARD")
print("=" * 60)
print(f"Probing Qs in replies: {score_card['probing_in_reply']}/{total}")
print(f"Red flags in replies:  {score_card['redflag_in_reply']}/{total}")
print(f"Rich agent notes:      {score_card['rich_notes']}/{total}")

all_pass = (
    score_card["probing_in_reply"] == total
    and score_card["redflag_in_reply"] >= total - 1  # turn 1 may not have red flag if not detected yet
    and score_card["rich_notes"] >= total - 1
    and all(intel.get(k) for k in ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses", "caseIds", "policyNumbers", "orderNumbers"])
    and d.get("confidenceLevel", 0) >= 0.7
    and d.get("engagementMetrics", {}).get("engagementDurationSeconds", 0) >= 100
)
print(f"\nOVERALL: {'ALL PASS' if all_pass else 'SOME FAILURES'}")
