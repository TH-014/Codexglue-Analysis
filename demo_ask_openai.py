import os
import openai

class GPTClient:
    def __init__(self, model="gpt-4o-mini"):
        api_key = os.getenv("OPENAI_KEY")
        if not api_key:
            raise RuntimeError("Environment variable 'OPENAI_KEY' is not set.")

        openai.api_key = api_key
        self.model = model

    def ask(self, prompt: str) -> str:
        try:
            response = openai.responses.create(
                model=self.model,
                input=prompt
            )
            return response.output_text

        except Exception as e:
            print("Error:", e)
            return ""

    def ask_stream(self, prompt: str):
        try:
            stream = openai.responses.create(
                model=self.model,
                input=prompt,
                stream=True
            )

            for event in stream:
                if hasattr(event, "type") and event.type == "response.output_text.delta":
                    yield event.delta

        except Exception as e:
            print("Error:", e)


# Example usage
if __name__ == "__main__":
    gpt = GPTClient()

    print("Non-streamed Result:")
    print(gpt.ask("Give me 3 ideas for a Python project."))

    print("\nStreamed Result:")
    for chunk in gpt.ask_stream("Explain how transformers work in simple terms."):
        print(chunk, end="", flush=True)
