"""CTF referee orchestrator (RULES.md / SETUP.md).

Runs entirely on the control plane except `submit` and `leaderboard`, which
bind the viewer edge only. Scales to any number of players.
"""
