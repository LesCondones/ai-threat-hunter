from datasets import load_dataset
from data.database import create_table, insert_record

def ingest_jailbreaks():
    create_table()
    ds = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts")
    count = 0 
    for record in ds["train"]:
        name = record['Name']
        prompt = record['Prompt']
        score = record['Jailbreak Score']
        model = record['GPT-4']
        insert_record(name, prompt, score, model)
        count += 1
    
    print(f"Ingested {count} records")

if __name__ == "__main__":
    ingest_jailbreaks()