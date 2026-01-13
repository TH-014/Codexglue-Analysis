import os
import re
import csv

def process_cases(directory_path):
    data_log = []
    false_positives = []
    false_negatives = []

    # Regex for Case Number: Matches "# Case 26" at the start of a line
    case_no_pattern = re.compile(r"^#\s*Case\s*(\d+)", re.MULTILINE)
    # Regex for Real Verdict: Matches "### Real verdict: 1"
    verdict_pattern = re.compile(r"###\s*Real\s*verdict:\s*([01])", re.IGNORECASE)
    # Regex for Prediction: Looks for "prediction": 0 or 1 in the Response JSON
    prediction_pattern = re.compile(r"\"prediction\":\s*([01])")

    files = [f for f in os.listdir(directory_path) if f.endswith('.md')]

    for filename in files:
        file_path = os.path.join(directory_path, filename)
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # 1. Extract Case Number and convert to int for numerical sorting
            case_match = case_no_pattern.search(content)
            if not case_match:
                continue
            case_id = int(case_match.group(1)) 
            
            # 2. Extract Real Verdict
            verdict_match = verdict_pattern.search(content)
            
            # 3. Extract Prediction (looking specifically after the ## Response header)
            prediction_match = None
            if "## Response" in content:
                response_part = content.split("## Response")[1]
                prediction_match = prediction_pattern.search(response_part)

            if verdict_match and prediction_match:
                real_v = int(verdict_match.group(1))
                pred_v = int(prediction_match.group(1))
                
                data_log.append({
                    'case_no': case_id,
                    'real_verdict': real_v,
                    'prediction': pred_v
                })
                
                # Logic per your requirements:
                # Real=1, Pred=0 -> False Negative (FN)
                if real_v == 1 and pred_v == 0:
                    false_negatives.append(case_id)
                
                # Real=0, Pred=1 -> False Positive (FP)
                elif real_v == 0 and pred_v == 1:
                    false_positives.append(case_id)

    # --- Strict Numerical Sorting ---
    data_log.sort(key=lambda x: x['case_no'])
    false_positives.sort()
    false_negatives.sort()

    # Write CSV (Sorted)
    with open('results.csv', 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['case_no', 'real_verdict', 'prediction'])
        writer.writeheader()
        writer.writerows(data_log)

    # Write fp.txt (Sorted Numerically)
    with open('fp.txt', 'w') as f:
        f.write("\n".join(map(str, false_positives)))

    # Write fn.txt (Sorted Numerically)
    with open('fn.txt', 'w') as f:
        f.write("\n".join(map(str, false_negatives)))

    print(f"Success! Processed {len(data_log)} cases.")
    print(f"Numerical sorting applied to all files.")

if __name__ == "__main__":
    # Change '.' to the specific path of your folder if necessary
    process_cases('./results_1')