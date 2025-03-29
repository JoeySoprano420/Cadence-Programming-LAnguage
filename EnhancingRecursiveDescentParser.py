class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0
    
    def current_token(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None
    
    def consume(self):
        self.pos += 1
    
    def parse_expression(self):
        left = self.parse_term()
        while self.current_token() and self.current_token()[0] in ('OPERATOR', 'PUNCTUATION'):
            token = self.current_token()
            if token[1] in ('+', '-'):
                self.consume()
                right = self.parse_term()
                left = (token[1], left, right)  # Add node in AST for addition/subtraction
        return left

    def parse_term(self):
        left = self.parse_factor()
        while self.current_token() and self.current_token()[0] in ('OPERATOR', 'PUNCTUATION'):
            token = self.current_token()
            if token[1] in ('*', '/'):
                self.consume()
                right = self.parse_factor()
                left = (token[1], left, right)  # Add node in AST for multiplication/division
        return left

    def parse_factor(self):
        token = self.current_token()
        if token[0] == 'NUMBER':
            self.consume()
            return ('NUMBER', token[1])
        elif token[0] == 'IDENTIFIER':
            self.consume()
            return ('IDENTIFIER', token[1])
        elif token[1] == '(':
            self.consume()
            expr = self.parse_expression()
            if self.current_token()[1] == ')':
                self.consume()
                return expr
            else:
                raise SyntaxError("Expected closing parenthesis")
        else:
            raise SyntaxError("Unexpected token")

# Example usage
parser = Parser(tokens)
ast = parser.parse_expression()
print(ast)
