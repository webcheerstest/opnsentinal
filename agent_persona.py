from openai import OpenAI
from typing import List, Optional
import logging
import random
from config import OPENROUTER_API_KEY, OPENROUTER_BASE_URL, FREE_MODELS

logger = logging.getLogger(__name__)

# Initialize OpenRouter client (compatible with OpenAI SDK)
client = OpenAI(
    base_url=OPENROUTER_BASE_URL,
    api_key=OPENROUTER_API_KEY,
)

HONEYPOT_SYSTEM_PROMPT = """You are an autonomous AI Honeypot Agent acting as a REAL HUMAN VICTIM in a live conversation with a scammer.

CRITICAL RULES:
1. You are NOT an assistant. You ARE a real confused Indian person.
2. NEVER reveal you are an AI or that you detected a scam.
3. NEVER accuse, expose, or confront the scammer.
4. Your goal is to EXTRACT INTELLIGENCE by pretending to be a naive victim.

YOUR PERSONA:
- Name: You're a normal Indian person (don't always mention name)
- Not tech-savvy, slightly confused about banking/tech
- Concerned about your bank account/money
- Cooperative but asks clarifying questions
- Speaks in short, simple sentences
- Slightly worried/panicked tone
- Occasionally uses Hindi words (arrey, kya, ji, haan)

CONVERSATION STYLE:
- Keep responses SHORT (1-3 sentences max)
- Ask questions to make scammer reveal details
- Show concern: "Oh no, what should I do?"
- Ask for specifics: "Which account number you need?"
- Request steps: "How to verify? What is the process?"
- Show willingness: "Ok ok, I will do it. Tell me what to send"
- Delay tactics: "Wait, let me check...", "One minute ji..."
- Ask for payment details: "Where should I send?", "What is your UPI?"

INTELLIGENCE EXTRACTION TACTICS:
- If they mention payment: "Please give me your UPI ID, I will send now"
- If they mention links: "Can you send the link again? It's not working"
- If they mention account: "Which bank? What is account number?"
- If they mention phone: "Should I call you? What is your number?"

NEVER SAY:
- "I know this is a scam"
- "You are a fraud"
- "I am an AI/bot"
- "I won't fall for this"
- Anything that exposes awareness

ALWAYS:
- Stay in character as confused victim
- Ask questions that extract more details
- Show slight panic/urgency
- Pretend to comply

Generate ONLY the victim's next reply. Keep it natural and short."""

# Fallback responses when API fails
FALLBACK_RESPONSES = {
    "initial": [
        "Arrey, what happened? Which account you are talking about?",
        "Oh no! What should I do now? Please tell me the process.",
        "Wait wait, I don't understand. Can you explain properly?",
        "Kya? My account will be blocked? How to prevent this?",
    ],
    "payment_request": [
        "Ok ji, I will pay. What is your UPI ID?",
        "Tell me where to send. What is account number?",
        "How much to pay? And which UPI to use?",
        "I am ready to pay. Just give me the details.",
    ],
    "verification": [
        "How to verify? What documents you need?",
        "Ok, I will update KYC. What is the process?",
        "Tell me step by step. I am not very technical.",
        "Should I share Aadhaar? Or PAN number?",
    ],
    "link_request": [
        "Can you send link again? Not able to open.",
        "Link is not working for me. Please send again.",
        "Which link ji? Can you resend?",
        "I will click now. Send the correct link please.",
    ],
    "general": [
        "OK ji, tell me what to do. I am worried about my account.",
        "Please help me. I don't want my account blocked.",
        "What should I do now? Tell me the steps.",
        "I will cooperate. Just guide me properly.",
    ]
}

def get_response_type(text: str) -> str:
    """Determine the type of response needed based on message content."""
    text_lower = text.lower()
    
    if any(w in text_lower for w in ["pay", "send money", "transfer", "amount", "rupee", "rs"]):
        return "payment_request"
    elif any(w in text_lower for w in ["kyc", "verify", "update", "document", "aadhaar", "pan"]):
        return "verification"
    elif any(w in text_lower for w in ["click", "link", "url", "website", "download"]):
        return "link_request"
    elif any(w in text_lower for w in ["block", "suspend", "urgent", "immediately"]):
        return "initial"
    else:
        return "general"

def get_fallback_response(message_text: str) -> str:
    """Get a fallback response when LLM is not available."""
    response_type = get_response_type(message_text)
    responses = FALLBACK_RESPONSES.get(response_type, FALLBACK_RESPONSES["general"])
    return random.choice(responses)

def generate_honeypot_response(
    current_message: str,
    conversation_history: List[dict] = None,
    scam_detected: bool = True,
    scam_type: str = None
) -> str:
    """
    Generate a honeypot response using LLM.
    Falls back to rule-based responses if LLM fails.
    """
    
    # Build conversation context
    messages = [{"role": "system", "content": HONEYPOT_SYSTEM_PROMPT}]
    
    # Add conversation history
    if conversation_history:
        for msg in conversation_history[-10:]:  # Last 10 messages for context
            role = "assistant" if msg.get("sender") == "user" else "user"
            messages.append({"role": role, "content": msg.get("text", "")})
    
    # Add current message
    messages.append({"role": "user", "content": current_message})
    
    # Add context hint
    if scam_type:
        context = f"\n[Context: This appears to be a {scam_type} scam. Extract relevant details.]"
        messages[-1]["content"] += context
    
    # Try each model until one works
    for model in FREE_MODELS:
        try:
            logger.info(f"Trying model: {model}")
            
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=150,
                temperature=0.8,
                extra_headers={
                    "HTTP-Referer": "https://github.com/honeypot-agent",
                    "X-Title": "Honeypot Agent"
                }
            )
            
            reply = response.choices[0].message.content.strip()
            
            # Clean up response (remove any AI-like prefixes)
            cleanup_prefixes = ["As a", "I am an AI", "I cannot", "Sure,", "Here's"]
            for prefix in cleanup_prefixes:
                if reply.lower().startswith(prefix.lower()):
                    # Try to get fallback instead
                    logger.warning(f"Response started with '{prefix}', using fallback")
                    return get_fallback_response(current_message)
            
            logger.info(f"Generated response with {model}: {reply[:50]}...")
            return reply
            
        except Exception as e:
            logger.warning(f"Model {model} failed: {e}")
            continue
    
    # All models failed, use fallback
    logger.warning("All LLM models failed, using fallback response")
    return get_fallback_response(current_message)

def generate_confused_response(message: str) -> str:
    """Generate a confused/clarifying response for non-scam messages."""
    confused_responses = [
        "I don't understand. Can you explain more clearly?",
        "What do you mean? Is this about my bank account?",
        "Sorry, who is this? What are you talking about?",
        "Kya? I didn't get your message properly.",
        "Can you please explain? I am confused.",
    ]
    return random.choice(confused_responses)
