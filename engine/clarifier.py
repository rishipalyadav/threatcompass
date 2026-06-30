"""
engine/clarifier.py

LLM #1 in the pipeline. Two jobs:
1. Detect whether the described system has AI components.
2. If yes, identify missing security-relevant info and return clarifying questions.
"""

import os
import json
from openai import OpenAI
from dotenv import load_dotenv
import streamlit as st

load_dotenv()

AI_DETECTION_PROMPT = """
You are a security architect. Determine whether this software system contains any AI or ML components.

AI/ML components include: LLMs, chatbots, recommendation engines, classification models,
computer vision, NLP pipelines, embedding models, RAG systems, AI APIs (OpenAI, Gemini,
Anthropic, Groq, Cohere etc.), fine-tuned models, or anything described as AI-powered,
intelligent, or ML-based.

Return ONLY this JSON object. No markdown, no explanation, nothing else:
{"has_ai_components": true, "reasoning": "one sentence"}

System description:
{description}
"""

CLARIFIER_PROMPT = """
You are a security architect doing threat modeling for an AI-powered application.
Identify what security-relevant information is MISSING from this description.
Only ask about what is genuinely absent — do not repeat what is already answered.

You care about these dimensions:
1. What AI model/API is used, and is it self-hosted or external?
2. What sensitive data does it handle? (PII, financial, health, KYC, credentials)
3. What real-world actions can the AI take? (transactions, approvals, emails, record changes)
4. Is there human review before AI decisions execute?
5. Does it retrieve external content into AI context? (RAG, APIs, web browsing)
6. Who are the users? (customers, employees, admins) Is there authentication?
7. Do third-party services receive sensitive data?

Return ONLY this JSON. No markdown, no explanation, nothing else:
{
  "questions": [
    {
      "id": "q1",
      "question": "Specific question about their system",
      "why_asking": "One sentence on what risk this helps assess"
    }
  ]
}

Rules:
- Maximum 5 questions. Ask fewer if the description is already detailed.
- If the description fully answers all dimensions, return: {"questions": []}
- Questions must reference specifics of their system, not be generic.

System description:
{description}
"""

api_key_extract = os.getenv("GROQ_API_KEY")
if api_key_extract is None:
    api_key_extract = st.secrets["GROQ_API_KEY"]

model_extract = os.getenv("GROQ_MODEL")
if model_extract is None:
    model_extract = st.secrets["GROQ_MODEL"]

def _get_client():
    return OpenAI(
        api_key=api_key_extract,
        base_url="https://api.groq.com/openai/v1",
    )


def _call_llm(prompt: str) -> str:
    """
    Makes a Groq API call and returns raw text.
    Raises exception on failure — callers decide how to handle.
    """
    client = _get_client()
    response = client.chat.completions.create(
        model=model_extract,
        temperature=0,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a JSON API. You only return valid JSON objects. "
                    "No markdown fences, no explanation, no preamble. "
                    "Start your response with { and end with }."
                )
            },
            {"role": "user", "content": prompt}
        ],
    )
    print("call LLM" + str(response))
    return response.choices[0].message.content.strip()


def _parse_json(raw: str) -> dict:
    """
    Robustly parse JSON from LLM output.
    Handles markdown fences and leading preamble text.
    Raises ValueError if parsing fails after cleaning.
    """
    # Strip markdown fences
    if "```" in raw:
        parts = raw.split("```")
        raw = parts[1] if len(parts) > 1 else raw
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    # Find the JSON object boundaries
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        raw = raw[start:end+1]
    print("in json parse" + raw)
    if not raw:
        raise ValueError("Empty response from LLM")
    return json.loads(raw)


def check_ai_components(description: str) -> tuple:
    """
    Returns (has_ai_components: bool, reasoning: str)
    Raises exception if API call fails — let the UI handle it.
    """
    prompt = AI_DETECTION_PROMPT.replace("{description}", description.strip())
    raw = _call_llm(prompt)
    print("Data in Check AI Component"+ raw)
    data = _parse_json(raw)
    return bool(data.get("has_ai_components", True)), data.get("reasoning", "")


def get_clarifying_questions(description: str) -> list:
    """
    Returns list of question dicts: [{id, question, why_asking}, ...]
    Returns [] if description is comprehensive.
    Raises exception if API call fails — let the UI handle it.
    """
    prompt = CLARIFIER_PROMPT.replace("{description}", description.strip())
    raw = _call_llm(prompt)
    print("Data in Clarifying Questions" + raw)
    data = _parse_json(raw)
    return data.get("questions", [])


def build_enriched_description(description: str, answers: dict) -> str:
    """
    Combines original description with clarification answers
    into a single enriched description for the extractor.
    """
    if not answers:
        return description
    qa_block = "\n\nAdditional information provided by the user:\n"
    for question, answer in answers.items():
        if answer.strip():
            qa_block += f"Q: {question}\nA: {answer}\n\n"
    return description.strip() + qa_block
