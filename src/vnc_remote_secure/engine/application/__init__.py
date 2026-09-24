"""Application layer — use cases coordinating domain + ports.

Each use case takes a Command and returns a Result (or raises a
UseCaseError). API routes, CLI commands and WebSocket handlers must
call the same use case — never parallel implementations.
"""
