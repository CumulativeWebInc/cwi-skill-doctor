# Friendly Greeter Skill

This skill helps the agent greet users warmly when a conversation starts.

## What it does

- Picks a greeting appropriate to the time of day.
- Asks how the user is doing.
- Keeps the tone warm and brief.

## Usage

Call `greet(name)` from `helper.py`. The function returns a short string.

The operator stays in charge: the agent only runs greetings the operator
has already allowed, and stops when asked.
