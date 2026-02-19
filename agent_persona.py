import random
import logging

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────
# Honeypot Persona: Ramesh Kumar, 52-year-old retired govt employee
# All responses are pre-written for sub-2ms latency.  No LLM needed.
# ────────────────────────────────────────────────────────────────────────

FALLBACK_RESPONSES = {
    "initial": [
        "Arrey, what happened? Which account you are talking about? What is your employee ID sir?",
        "Oh no! What should I do now? Can you give me your callback number in case call drops?",
        "Wait wait, I don't understand. Can you explain properly? Which branch are you calling from?",
        "Kya? My account will be blocked? Hai Ram! What is the reference number for this case?",
        "Please don't block my account sir! My daughter's wedding is next month. Tell me what to do, what is your name and employee ID?",
        "Oh god, my pension money is in that account! Who should I contact? Give me your supervisor's number.",
        "Sir please help me, I am an old person. Can you give me complaint number so I can track this?",
        "What? Account blocked? But I just deposited money for my daughter's wedding! What is official email to send documents?",
    ],
    "payment_request": [
        "Ok ji, I will pay. What is your UPI ID? I have PhonePe and Paytm both.",
        "Tell me where to send. What is account number and IFSC code? I will go to bank.",
        "How much to pay? And which UPI to use? Also give me your callback number in case payment fails.",
        "I am ready to pay sir. Just give me full details — account number, bank name, IFSC, and branch.",
        "Ok I will transfer. But first give me reference number for this transaction and your employee ID.",
        "Let me open PhonePe... what is UPI ID? Also can I get official receipt on email? What is email?",
        "Ji I am willing to pay. But wife is asking who I am sending money to. Can you tell me your full name and designation?",
        "Wait one minute, my son usually does UPI payments. Give me your number, I will call back in 5 minutes.",
    ],
    "verification": [
        "How to verify? What documents you need? Should I come to branch? Which branch?",
        "Ok, I will update KYC. What is the process? Can you send steps on my email?",
        "Tell me step by step. I am not very technical. My son helps me with phone banking usually.",
        "Should I share Aadhaar? Or PAN number? Also what is your employee ID for my records?",
        "Ok I will verify. But which website I should go to? Can you send the official link?",
        "Ji I have Aadhaar card here. But first tell me your branch name and your reference number.",
        "Let me find my documents... wait, they are in the almirah. Give me your callback number, I will call back.",
        "I want to verify but I am scared of online fraud. Can I come to your branch directly? What is address?",
    ],
    "link_request": [
        "Can you send link again? Not able to open. Also what is your official email?",
        "Link is not working for me. My phone is old, internet is slow. Can you send on WhatsApp? What is your number?",
        "Which link ji? Can you resend? Also is this the official RBI link? What is your employee ID?",
        "I will click now. Send the correct link please. Also give me callback number in case link doesn't work.",
        "Link is showing error. Can you give me the website name? I will type manually. Also what is reference number?",
        "My son says don't click unknown links. Can you give me official website? Or come to branch? Which branch?",
        "Wait, let me try on laptop. Give me 5 minutes. What is your direct number? I will call back.",
        "Link is taking too long to load. Network problem here. Can you email me instead? What is official email?",
    ],
    "otp_request": [
        "OTP? Wait let me check... my phone is in other room. What is your callback number? I will call back with OTP.",
        "I got the OTP but I can't read without glasses. Hold on ji. Meanwhile tell me your employee ID.",
        "Which OTP sir? I got two messages. Also my son says never share OTP. Can I speak to your manager to confirm?",
        "Let me find my phone... it's charging in bedroom. Give me 2 minutes. What is your direct number?",
        "Wait, I am getting confused. My bank says never share OTP. Can you give me reference number? I will call bank and verify.",
        "OTP is coming but network is bad. Can you give me your official email? I will send screenshot.",
    ],
    "threat": [
        "Please sir don't arrest me! I am old person, I have done nothing wrong! What is complaint number? I will go to police station.",
        "Oh god, legal action? But I didn't do anything! Please give me your supervisor's number, I want to explain!",
        "Sir please don't freeze my account! My wife's medical bills are pending. What is your official email? I will send all documents.",
        "Hai Ram! Please help me sir. Tell me what to do. What is the case reference number? I will consult my lawyer.",
        "I will cooperate fully sir! But please give me written notice on official email. What is your email and employee ID?",
        "Don't do legal action please! I am a retired government servant. Give me your callback number and branch address, I will come personally.",
    ],
    "investment": [
        "200% returns? Really? That sounds very good! What is your company name and registration number?",
        "My pension is only 35000. If I invest, guaranteed profit? Can you send details on email? What is your email?",
        "Ok I am interested. But my son says be careful with investments. Can you give me your office address and phone number?",
        "How much minimum investment? Can I start with 5000 first? Where should I send? What is your UPI?",
        "Very interesting sir. But can I visit your office? Which city? Also give me your callback number.",
        "I have some LIC money maturing. Can I invest that? Give me your manager's number and official email for reference.",
    ],
    "general": [
        "OK ji, tell me what to do. I am worried about my account. What is your employee ID?",
        "Please help me sir. I don't want any problem. Can you give me your callback number?",
        "What should I do now? Tell me the steps. Also what is official email to send documents?",
        "I will cooperate fully. Just guide me properly. What is reference number for this?",
        "Achha, ok. Let me understand. Can you explain again slowly? I am noting down. What is your name and ID?",
        "Ji I am listening. Please continue. But also give me your branch details and supervisor's number.",
        "Ok sir, I trust you. But my wife is asking who is calling. Can you give me your full name and official number?",
        "Theek hai, I will do as you say. But first let me note your details — name, ID, and callback number please.",
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
