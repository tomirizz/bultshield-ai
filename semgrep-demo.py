"""Static-analysis fixture only. Never imported or called by BultShield.
No real credential, input, network request, or command is used here.
"""


def unsafe_example_for_scanner(untrusted_text):
    # Deliberately unsafe pattern for the Semgrep demonstration.
    return eval(untrusted_text)
