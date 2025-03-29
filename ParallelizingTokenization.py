import re
import threading
from concurrent.futures import ThreadPoolExecutor

# Example patterns (extend as needed)
token_patterns = {
    'KEYWORD': r'\b(if|else|while|for|return)\b',
    'IDENTIFIER': r'[a-zA-Z_][a-zA-Z0-9_]*',
    'NUMBER': r'\d+',
    'OPERATOR': r'[+\-*/=]',
    'PUNCTUATION': r'[(){};]',
}

# A thread-safe structure for storing tokens
tokens = []

# Tokenizer function
def tokenize_chunk(text_chunk, chunk_start_idx):
    local_tokens = []
    for token_type, pattern in token_patterns.items():
        for match in re.finditer(pattern, text_chunk):
            local_tokens.append((token_type, match.group(), match.start() + chunk_start_idx))
    return local_tokens

# Main tokenizer using thread pooling
def tokenize(input_text):
    chunk_size = len(input_text) // 4  # Split input into 4 chunks
    chunks = [input_text[i:i+chunk_size] for i in range(0, len(input_text), chunk_size)]
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = executor.map(lambda chunk: tokenize_chunk(chunk[0], chunk[1]), zip(chunks, range(0, len(input_text), chunk_size)))
    
    all_tokens = []
    for result in results:
        all_tokens.extend(result)
    
    return sorted(all_tokens, key=lambda x: x[2])  # Sort by position

# Example usage
input_code = "if x == 10 { return x + 1; }"
tokens = tokenize(input_code)
print(tokens)
