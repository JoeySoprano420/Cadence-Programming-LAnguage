class TokenizerError(Exception):
    def __init__(self, message, line, column):
        super().__init__(message)
        self.line = line
        self.column = column

def tokenize_with_error_handling(input_text):
    line = 1
    column = 1
    tokens = []
    
    i = 0
    while i < len(input_text):
        char = input_text[i]
        if char == '\n':
            line += 1
            column = 1
        elif char in " \t":
            column += 1
        else:
            matched = False
            for token_type, pattern in token_patterns.items():
                match = re.match(pattern, input_text[i:])
                if match:
                    tokens.append((token_type, match.group(), line, column))
                    i += len(match.group())
                    column += len(match.group())
                    matched = True
                    break
            if not matched:
                raise TokenizerError(f"Unrecognized character '{char}'", line, column)
        i += 1
    
    return tokens

try:
    tokens = tokenize_with_error_handling(input_code)
except TokenizerError as e:
    print(f"Error: {e.message} at line {e.line}, column {e.column}")
