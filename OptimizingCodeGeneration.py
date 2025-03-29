def optimize_ast(ast):
    if isinstance(ast, tuple):
        if ast[0] == 'NUMBER' and isinstance(ast[1], int):
            return ast  # Constant number
        elif ast[0] in ('+', '-', '*', '/'):
            left = optimize_ast(ast[1])
            right = optimize_ast(ast[2])
            if isinstance(left, tuple) and left[0] == 'NUMBER' and isinstance(left[1], int):
                if isinstance(right, tuple) and right[0] == 'NUMBER' and isinstance(right[1], int):
                    if ast[0] == '+':
                        return ('NUMBER', left[1] + right[1])
                    elif ast[0] == '-':
                        return ('NUMBER', left[1] - right[1])
                    elif ast[0] == '*':
                        return ('NUMBER', left[1] * right[1])
                    elif ast[0] == '/':
                        return ('NUMBER', left[1] // right[1])
            return (ast[0], left, right)
    return ast
