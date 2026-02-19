import random
import logging

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────
# Honeypot Persona: Ramesh Kumar, 52-year-old retired govt employee
# All responses are pre-written for sub-2ms latency.  No LLM needed.
# ────────────────────────────────────────────────────────────────────────

FALLBACK_RESPONSES = {
    "initial": [
        "Arrey, what happened? Which account you are talking about? What is your employee ID sir? This sounds very urgent and suspicious.",
        "Oh no! What should I do now? Can you give me your callback number in case call drops? I find it suspicious that you are calling so urgently.",
        "Wait wait, I don't understand. Can you explain properly? Which branch are you calling from? Your urgency is making me suspicious.",
        "Kya? My account will be blocked? Hai Ram! What is the reference number for this case? This feels like those fraud calls my son warned me about.",
        "Please don't block my account sir! My daughter's wedding is next month. Tell me what to do, what is your name, employee ID, and office address?",
        "Oh god, my pension money is in that account! Who should I contact? Give me your supervisor's number and your official website.",
        "Sir please help me, I am an old person. Can you give me complaint number so I can track this? Also what is your company registration number?",
        "What? Account blocked? But I just deposited money! What is official email to send documents? Can you also share your ID card on WhatsApp?",
    ],
    "payment_request": [
        "Ok ji, I will pay. What is your UPI ID? I have PhonePe and Paytm both. But asking for payment is a red flag — are you really from the bank?",
        "Tell me where to send. What is account number and IFSC code? I will go to bank. But my son says real banks never ask for money over phone.",
        "How much to pay? And which UPI to use? Also give me your callback number. It is suspicious that you need payment so urgently.",
        "I am ready to pay sir. Just give me full details — account number, bank name, IFSC, branch, and your official website for verification.",
        "Ok I will transfer. But first give me reference number for this transaction, your employee ID, and your office address so I can visit.",
        "Let me open PhonePe... what is UPI ID? Also can I get official receipt on email? What is email? Demanding urgent payment is very suspicious.",
        "Ji I am willing to pay. But wife is asking who I am sending money to. Can you tell me your full name, designation, and company registration?",
        "Wait one minute, my son usually does UPI payments. Give me your number, I will call back. Can you also share your ID card photo for verification?",
    ],
    "verification": [
        "How to verify? What documents you need? Should I come to branch? Which branch? Asking for documents over phone is a red flag.",
        "Ok, I will update KYC. What is the process? Can you send steps on my email? My son says banks never ask for KYC over phone calls.",
        "Tell me step by step. I am not very technical. But isn't it suspicious to ask for verification over phone? What is your office address?",
        "Should I share Aadhaar? Or PAN number? Also what is your employee ID for my records? Asking for Aadhaar on phone is a major red flag.",
        "Ok I will verify. But which website I should go to? Can you send the official link? I want to verify on the real bank website only.",
        "Ji I have Aadhaar card here. But first tell me your branch name, reference number, and supervisor's direct number for verification.",
        "Let me find my documents... wait, they are in the almirah. Give me your callback number and your official company email ID.",
        "I want to verify but I am scared of online fraud. Can I come to your branch directly? What is full address and your manager's name?",
    ],
    "link_request": [
        "Can you send link again? Not able to open. Also what is your official email? Sending unknown links is a major red flag for phishing.",
        "Link is not working for me. My phone is old. Can you send on WhatsApp? What is your number? But my son says clicking unknown links is dangerous.",
        "Which link ji? Can you resend? Also is this the official RBI link? What is your employee ID? Unknown links are a suspicious red flag.",
        "I will click now. Send the correct link please. Also give me callback number. But this link looks different from my bank's official website.",
        "Link is showing error. Can you give me the website name? I will type manually. Also what is your reference number and office address?",
        "My son says don't click unknown links — it could be phishing. Can you give me official website? Or come to branch? Which branch?",
        "Wait, let me try on laptop. Give me 5 minutes. What is your direct number and official email? Sending unknown links is very suspicious.",
        "Link is taking too long to load. Can you email me instead? What is official email? But this link URL looks suspicious, not like a real bank.",
    ],
    "otp_request": [
        "OTP? Wait let me check... my phone is in other room. What is your callback number? But asking for OTP is a major red flag — banks never ask for OTP!",
        "I got the OTP but I can't read without glasses. Hold on ji. Meanwhile tell me your employee ID. My son says sharing OTP is very dangerous.",
        "Which OTP sir? I got two messages. Also my son says never share OTP — this is a big red flag. Can I speak to your manager to confirm?",
        "Let me find my phone... it's charging in bedroom. Give me 2 minutes. What is your direct number? But OTP sharing is suspicious, banks warn against it.",
        "Wait, I am getting confused. My bank says never share OTP — this is the biggest red flag. Can you give me reference number? I will call bank and verify.",
        "OTP is coming but network is bad. Can you give me your official email? I will send screenshot. But asking OTP is extremely suspicious.",
    ],
    "threat": [
        "Please sir don't arrest me! I am old person! What is complaint number? But threatening is a red flag — real officers don't threaten on phone!",
        "Oh god, legal action? But I didn't do anything! Please give me your supervisor's number. Threatening customers is very suspicious behavior.",
        "Sir please don't freeze my account! What is your official email? I will send all documents. But my son says real police gives written notice, not calls.",
        "Hai Ram! Please help me sir. What is the case reference number? I will consult my lawyer. Using threats to create urgency is a classic scam red flag.",
        "I will cooperate fully sir! But please give me written notice on official email. What is your email, employee ID, and police station address?",
        "Don't do legal action please! I am a retired government servant. Give me your callback number and station address. Threats and urgency are red flags.",
    ],
    "investment": [
        "200% returns? Really? That sounds very good! What is your company name and registration number? But guaranteed returns is a red flag for fraud.",
        "My pension is only 35000. If I invest, guaranteed profit? Can you send details on email? What is your email? Guaranteed returns sounds suspicious.",
        "Ok I am interested. But my son says be careful. Can you give me your office address, phone number, and SEBI registration number?",
        "How much minimum investment? Where should I send? What is your UPI? But promising high returns is a classic investment scam red flag.",
        "Very interesting sir. But can I visit your office? Which city? Also give me your callback number and company website for verification.",
        "I have some LIC money maturing. Can I invest? Give me your manager's number, official email, and SEBI registration. High returns is suspicious.",
    ],
    "general": [
        "OK ji, tell me what to do. I am worried about my account. What is your employee ID and office address? This whole call is making me suspicious.",
        "Please help me sir. I don't want any problem. Can you give me your callback number and your company's official website for verification?",
        "What should I do now? Tell me the steps. Also what is official email to send documents? And your full name and designation?",
        "I will cooperate fully. Just guide me properly. What is reference number, your direct phone number, and your supervisor's name?",
        "Achha, ok. Let me understand. Can you explain again slowly? I am noting down. What is your name, ID, and office address?",
        "Ji I am listening. Please continue. But also give me your branch details, supervisor's number, and company registration number.",
        "Ok sir, I trust you. But my wife is asking who is calling. Can you give me your full name, official number, and identity proof?",
        "Theek hai, I will do as you say. But first let me note your details — name, ID, callback number, and which department exactly?",
    ],
}


def _classify(text: str) -> str:
    """Classify message into a response category."""
    t = text.lower()

    if any(w in t for w in ["otp", "pin", "cvv", "password", "code", "one time"]):
        return "otp_request"
    if any(w in t for w in ["arrest", "police", "legal", "court", "jail", "fine", "penalty", "case filed", "fir"]):
        return "threat"
    if any(w in t for w in ["invest", "bitcoin", "crypto", "trading", "returns", "profit", "guaranteed", "mutual fund"]):
        return "investment"
    if any(w in t for w in ["pay", "send money", "transfer", "amount", "rupee", "rs ", "rs.", "fee", "charge"]):
        return "payment_request"
    if any(w in t for w in ["kyc", "verify", "update", "document", "aadhaar", "pan", "aadhar"]):
        return "verification"
    if any(w in t for w in ["click", "link", "url", "website", "download", "http", "www"]):
        return "link_request"
    if any(w in t for w in ["block", "suspend", "urgent", "immediately", "deactivat", "frozen", "expire"]):
        return "initial"
    return "general"


def generate_honeypot_response(current_message: str, **kwargs) -> str:
    """
    Generate a fast, deterministic honeypot response.
    No LLM — guaranteed sub-2ms.
    """
    category = _classify(current_message)
    responses = FALLBACK_RESPONSES.get(category, FALLBACK_RESPONSES["general"])
    return random.choice(responses)


def generate_confused_response(message: str) -> str:
    """Generate a confused/clarifying response for non-scam messages."""
    confused = [
        "I don't understand. Can you explain more clearly? Who is this calling?",
        "What do you mean? Is this about my bank account? What is your name sir?",
        "Sorry, who is this? What are you talking about? Which company are you calling from?",
        "Kya? I didn't get your message properly. Can you give me your callback number?",
        "Can you please explain? I am confused. Are you from the bank? What is your employee ID?",
        "Arrey, I don't understand. My son handles all this. Give me your number, I will call back.",
        "What is this about? I am a retired person, I don't understand technical things. Explain simply please.",
        "Sorry ji, who gave you my number? Is this regarding my SBI account? What is your reference number?",
    ]
    return random.choice(confused)
