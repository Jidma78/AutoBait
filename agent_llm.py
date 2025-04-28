import openai
import os
import pathlib

BASE = pathlib.Path(__file__).resolve().parent
SYS_PROMPT = (BASE / "prompt/system.txt").read_text()
SCENARIO = (BASE / "prompt/scenario.txt").read_text()
PROFILE_PROMPT_TEMPLATE = (BASE / "prompt/profile_attacker.txt").read_text()

openai.api_key = os.getenv("OPENROUTER_API_KEY")
openai.api_base = "https://openrouter.ai/api/v1"

async def llm_ask(cmd, profile_mode=False):
    """
    Asks the LLM a question or provides input, optionally in profile mode.
    """
    try:
        if profile_mode:
            assert isinstance(cmd, dict)
            prompt_text = PROFILE_PROMPT_TEMPLATE.format(
                ip=cmd["ip"],
                commands="\n".join(cmd["commands"])
            )
        else:
            prompt_text = cmd

        print(f"\n[DEBUG] Prompt sent to the LLM :\n{prompt_text}\n")

        response = await openai.ChatCompletion.acreate(
            model="anthropic/claude-3-sonnet-20240229",
            messages=[
                {"role": "system", "content": SYS_PROMPT},
                {"role": "system", "content": SCENARIO},
                {"role": "user", "content": prompt_text},
            ],
            temperature=0.1,
            max_tokens=800, 
        )

        print("\n[DEBUG] Raw response from OpenRouter :", response)

        return response['choices'][0]['message']['content'].strip()

    except Exception as e:
        print(f"[❌] LLM error : {e}")
        return f"[❌ LLM error] {e}"
