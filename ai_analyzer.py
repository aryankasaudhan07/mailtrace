"""
ai_analyzer.py
--------------
Week 2 of the build plan: sends the email BODY TEXT to Claude and gets
back a structured risk assessment — urgency cues, impersonation
language, suspicious links, and an overall verdict.

This is the "NLP-based analysis" component of the problem statement,
done via prompting instead of training a model from scratch.

Requires:
    pip install anthropic

Set your API key as an environment variable before running:
    export ANTHROPIC_API_KEY=your_key_here
"""

import os
import json
import re
from anthropic import Anthropic

client = Anthropic()  # reads ANTHROPIC_API_KEY from environment

MODEL = "claude-sonnet-4-6"  # swap for whichever model your team has access to

SYSTEM_PROMPT = """You are a cybersecurity analyst assistant specializing in email fraud detection.
You will be given the subject and body text of an email. Analyze it for signs of phishing,
impersonation, business email compromise (BEC), or social engineering.

Respond with ONLY a JSON object — no preamble, no markdown fences, no extra text.
The JSON must have exactly this shape:

{
  "urgency_score": <integer 0-10, how much artificial urgency/pressure is used>,
  "impersonation_likelihood": <integer 0-10, how likely this impersonates a real person/brand/authority>,
  "suspicious_link_flags": [<list of short strings describing any suspicious link patterns found, e.g. "shortened URL", "mismatched display text vs href", "IP-address link">],
  "social_engineering_tactics": [<list of short strings naming tactics used, e.g. "fear of account suspension", "fake invoice", "authority impersonation", "reward/prize lure">],
  "overall_verdict": <one of: "benign", "suspicious", "likely_phishing">,
  "confidence": <integer 0-100>,
  "reasoning": "<one or two sentence plain-English explanation for a non-technical dashboard viewer>"
}

Be calibrated: most ordinary marketing or transactional email should score low. Only flag genuine
red flags — do not invent risk that isn't supported by the text."""


def analyze_email_body(subject: str, body: str) -> dict:
    """Sends subject + body to Claude and parses the structured JSON verdict."""
    user_message = f"Subject: {subject}\n\nBody:\n{body[:6000]}"  # cap length for cost/safety

    response = client.messages.create(
        model=MODEL,
        max_tokens=500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    raw_text = "".join(
        block.text for block in response.content if block.type == "text"
    )

    # Defensive parsing: strip stray code fences if the model adds them anyway
    cleaned = re.sub(r"^```(json)?|```$", "", raw_text.strip(), flags=re.MULTILINE).strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {
            "error": "Failed to parse AI response as JSON",
            "raw_response": raw_text,
        }


if __name__ == "__main__":
    # Quick manual test
    sample_subject = "URGENT: Your account will be suspended in 24 hours"
    sample_body = (
        "Dear Customer,\n\nWe detected unusual activity on your account. "
        "Click here immediately to verify your identity or your account "
        "will be permanently locked: http://secure-login-verify.tk/reset\n\n"
        "Failure to act within 24 hours will result in suspension.\n\nBank Security Team"
    )
    result = analyze_email_body(sample_subject, sample_body)
    print(json.dumps(result, indent=2))
