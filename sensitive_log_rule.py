"""Low-noise static check for sensitive values passed to Android log sinks.

This deliberately requires a sensitive value expression in the message argument.
Labels and unrelated words in tags or exception arguments are not evidence that
the value itself is logged. It does not establish release-build reachability.
"""

import re


LOG_SINK = re.compile(
    r'\b(?:Log\.(?:d|e|i|v|w|wtf|println)|System\.(?:out|err)\.print(?:ln)?)\s*\('
)
SENSITIVE_NAME = re.compile(
    r'(?i)(?<![\w$])(?:get|read)?(?:password|passwd|passphrase|passcode|passwordHash|'
    r'access_?token|refresh_?token|auth_?token|id_?token|bearer_?token|session_?token|'
    r'api_?key|client_?secret|secret_?key|private_?key|session_?id|session_?cookie|'
    r'authorization_?header|credit_?card(?:_?number)?|card_?number|cvv|ssn|'
    r'auth_?pin|user_?pin|payment_?pin|transaction_?pin|pin_?code)(?!\w)'
)
KOTLIN_INTERPOLATION = re.compile(r'(?<!\\)\$(?:\{([^}]+)\}|([A-Za-z_][\w]*))')


def _mask_non_code(line):
    """Keep offsets while hiding quoted text and same-line comments."""
    masked = list(line)
    quote = None
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            masked[index] = ' '
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
            masked[index] = ' '
        elif line.startswith('//', index):
            masked[index:] = ' ' * (len(line) - index)
            break
        elif line.startswith('/*', index):
            end = line.find('*/', index + 2)
            end = len(line) if end == -1 else end + 2
            masked[index:end] = ' ' * (end - index)
            index = end - 1
        index += 1
    return ''.join(masked)


def _call_arguments(line, opening_paren):
    """Return top-level arguments of a complete, single-line call."""
    args = []
    start = opening_paren + 1
    depth = 1
    quote = None
    escaped = False
    for index in range(start, len(line)):
        char = line[index]
        if quote:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth == 0:
                args.append(line[start:index])
                return args
        elif char == ',' and depth == 1:
            args.append(line[start:index])
            start = index + 1
    return []


def _value_expressions(message):
    """Exclude literal prose while retaining Kotlin string interpolation."""
    expressions = []

    def replace_literal(match):
        literal = match.group()
        expressions.extend(part for interpolation in KOTLIN_INTERPOLATION.finditer(literal)
                           for part in interpolation.groups() if part)
        return ' ' * len(literal)

    outside = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                     replace_literal, message)
    expressions.append(outside)
    return expressions


def logs_sensitive_value(line):
    """True only when a log message contains a clearly named sensitive value."""
    for match in LOG_SINK.finditer(_mask_non_code(line)):
        args = _call_arguments(line, match.end() - 1)
        if not args:
            continue
        sink = match.group()
        message_index = 2 if 'Log.println' in sink else 1 if 'Log.' in sink else 0
        if len(args) <= message_index:
            continue
        if any(SENSITIVE_NAME.search(expression) for expression in _value_expressions(args[message_index])):
            return True
    return False
