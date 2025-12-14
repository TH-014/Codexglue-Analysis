import os
import openai
import json
import random
from pathlib import Path
import re
import time

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


def load_and_sample_data(file_path: str, n_insecure: int = 60, n_secure: int = 40):
    """Load JSONL file and randomly sample objects based on target value."""
    insecure_samples = []
    secure_samples = []
    
    with open(file_path, 'r') as f:
        for line in f:
            obj = json.loads(line.strip())
            if obj['target'] == 1:
                insecure_samples.append(obj)
            elif obj['target'] == 0:
                secure_samples.append(obj)
    
    # Randomly sample
    selected_insecure = random.sample(insecure_samples, min(n_insecure, len(insecure_samples)))
    selected_secure = random.sample(secure_samples, min(n_secure, len(secure_samples)))
    
    # Combine and return
    all_samples = selected_insecure + selected_secure
    random.shuffle(all_samples)  # Shuffle to mix insecure and secure
    
    return all_samples


def create_prompt(source_code: str) -> str:
    """Create the prompt for vulnerability detection."""
    prompt = f"""Given a source code, the task is to identify whether it is an insecure code that may attack software systems, such as resource leaks, use-after-free vulnerabilities and DoS attack. Treat the task as binary classification (0/1), where 1 stands for insecure code and 0 for secure code.

```
{source_code}
```

Output Format:
```
{{
    "prediction": 1,
    "line no": 10,
    "explanation": "----<explain why you classify this as insecure>------"
}}
```

or

```
{{
    "prediction": 0,
    "line no": 0,
    "explanation": "<how is this secure>"
}}
```

Strictly follow this output format."""
    
    return prompt


def parse_response(response: str) -> dict:
    """Parse the GPT response to extract prediction, line no, and explanation."""
    try:
        # Try to find JSON in the response
        json_match = re.search(r'\{[^}]*"prediction"[^}]*\}', response, re.DOTALL)
        if json_match:
            json_str = json_match.group(0)
            result = json.loads(json_str)
            return result
        else:
            # Fallback parsing
            prediction = 0
            if '"prediction": 1' in response or "'prediction': 1" in response:
                prediction = 1
            return {"prediction": prediction, "line no": 0, "explanation": "Could not parse response"}
    except Exception as e:
        print(f"Error parsing response: {e}")
        return {"prediction": 0, "line no": 0, "explanation": "Parse error"}


def create_markdown_file(case_num: int, obj: dict, prompt: str, response: str, parsed_result: dict, output_dir: str = "results"):
    """Create a markdown file for each case similar to the provided example."""
    Path(output_dir).mkdir(exist_ok=True)
    
    real_verdict = obj['target']
    predicted_verdict = parsed_result.get('prediction', 0)
    verdict_matched = "Yes" if real_verdict == predicted_verdict else "No"
    
    timestamp = int(time.time() * 1000)
    filename = f"{timestamp}_case{case_num}.md"
    filepath = os.path.join(output_dir, filename)
    
    markdown_content = f"""# Case {case_num}

### Real verdict: {real_verdict}
### Commit Id: {obj['commit_id']}

## Prompt:

\"\"\"Given a source code, the task is to identify whether it is an insecure code that may attack software systems, such as resource leaks, use-after-free vulnerabilities and DoS attack.  Treat the task as binary classification (0/1), where 1 stands for insecure code and 0 for secure code.

```
{obj['func']}
```

Output Format:
```
{{
    "prediction": 1,
    "line no": <which line causes the threat>,
    "explanation": "----<explain why you classify this as insecure>------"
}}
```

or

```
{{
    "prediction": 0,
    "line no": 0,
    "explanation": "<how is this secure>"
}}
```

Strictly follow this output format.\"\"\"


## Response:

{response}

## Verdict matched?:  {verdict_matched}"""
    
    with open(filepath, 'w') as f:
        f.write(markdown_content)
    
    print(f"Created {filename}")


def calculate_confusion_matrix(results: list):
    """Calculate and display confusion matrix."""
    tp = sum(1 for r in results if r['real'] == 1 and r['predicted'] == 1)
    tn = sum(1 for r in results if r['real'] == 0 and r['predicted'] == 0)
    fp = sum(1 for r in results if r['real'] == 0 and r['predicted'] == 1)
    fn = sum(1 for r in results if r['real'] == 1 and r['predicted'] == 0)
    
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print("\n" + "="*60)
    print("CONFUSION MATRIX")
    print("="*60)
    print(f"\n                Predicted")
    print(f"                 0    1")
    print(f"Actual    0    {tn:4d} {fp:4d}")
    print(f"          1    {fn:4d} {tp:4d}")
    print("\n" + "="*60)
    print(f"True Positives (TP):  {tp}")
    print(f"True Negatives (TN):  {tn}")
    print(f"False Positives (FP): {fp}")
    print(f"False Negatives (FN): {fn}")
    print(f"\nAccuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print("="*60)


# Main execution
if __name__ == "__main__":
    # Initialize GPT client
    gpt = GPTClient()
    
    # Load and sample data
    print("Loading and sampling data from train.jsonl...")
    samples = load_and_sample_data("train.jsonl", n_insecure=120, n_secure=80)
    print(f"Total samples selected: {len(samples)}")
    
    # Process each sample
    results = []
    
    for idx, obj in enumerate(samples, 1):
        print(f"\nProcessing case {idx}/{len(samples)}...")
        
        # Create prompt
        prompt = create_prompt(obj['func'])
        
        # Get response from GPT
        print(f"  Sending prompt to OpenAI...")
        response = gpt.ask(prompt)
        
        # Parse response
        parsed_result = parse_response(response)
        
        # Store result for confusion matrix
        results.append({
            'real': obj['target'],
            'predicted': parsed_result.get('prediction', 0)
        })
        
        # Create markdown file
        create_markdown_file(idx, obj, prompt, response, parsed_result)
        
        print(f"  Real: {obj['target']}, Predicted: {parsed_result.get('prediction', 0)}")
        
        # Small delay to avoid rate limiting
        time.sleep(0.5)
    
    # Calculate and display confusion matrix
    calculate_confusion_matrix(results)
    
    print(f"\nAll markdown files saved in 'results/' directory")