import os

from dotenv import load_dotenv
from groq import Groq


# Load variables from .env
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

# Create Groq client only if the key exists
client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None


def generate_ai_analysis(
    scan_type,
    input_data,
    risk_score,
    risk_level,
    reasons
):
    """
    Generate a cybersecurity threat analysis using Groq.

    If the API is unavailable, the application returns
    a fallback analysis instead of crashing.
    """

    # Convert detection reasons into readable text
    reasons_text = "\n".join(
        f"- {reason}" for reason in reasons
    )

    # --------------------------------------------------
    # Fallback if API key is missing
    # --------------------------------------------------
    if not client:
        if risk_score >= 60:
            recommendation = (
                "Do not interact with this content. "
                "Avoid clicking suspicious links, opening "
                "unknown attachments, or providing sensitive "
                "information."
            )
        elif risk_score >= 30:
            recommendation = (
                "Treat this content with caution. "
                "Verify the sender or website independently "
                "before taking any action."
            )
        else:
            recommendation = (
                "No major phishing indicators were detected. "
                "Continue using normal security precautions."
            )

        return {
            "success": True,
            "ai_enabled": False,
            "analysis": (
                f"The {scan_type} scan received a risk score "
                f"of {risk_score}/100 and was classified as "
                f"{risk_level}.\n\n"
                f"Detection indicators:\n{reasons_text}"
            ),
            "recommendation": recommendation
        }

    # --------------------------------------------------
    # Prompt for the AI
    # --------------------------------------------------
    prompt = f"""
You are a cybersecurity threat-analysis assistant.

Analyze the following phishing detection result.

SCAN TYPE:
{scan_type}

INPUT:
{input_data}

RISK SCORE:
{risk_score}/100

RISK LEVEL:
{risk_level}

DETECTION REASONS:
{reasons_text}

Give the response in four sections:

1. Threat Explanation
Explain clearly why this content may be suspicious.

2. Suspicious Indicators
Explain the most important indicators detected.

3. Recommended Action
Tell the user what they should do.

4. Security Verdict
Give a short final verdict.

Do not claim that something is definitely malicious unless
the evidence supports that conclusion.
"""

    # --------------------------------------------------
    # Call Groq
    # --------------------------------------------------
    try:

        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity threat-analysis "
                        "assistant. Provide accurate, concise and "
                        "easy-to-understand security explanations."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2,
            max_tokens=700
        )

        # Extract generated text
        analysis = response.choices[0].message.content

        return {
            "success": True,
            "ai_enabled": True,
            "analysis": analysis,
            "recommendation": (
                "Follow the security recommendations "
                "provided in the AI analysis."
            )
        }

    # --------------------------------------------------
    # Detailed error handling
    # --------------------------------------------------
    except Exception as error:

        print("\n========== GROQ AI ERROR ==========")
        print(repr(error))
        print("===================================\n")

        return {
            "success": False,
            "ai_enabled": True,
            "analysis": (
                "Groq AI analysis could not be generated."
            ),
            "recommendation": (
                "Use the risk score and detection reasons "
                "to make a security decision."
            ),
            "error": str(error)
        }