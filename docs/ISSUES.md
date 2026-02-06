# ISSUES.md - Comprehensive Audit Report

Catalogs every potential issue, concern, suboptimal pattern, edge case, and architectural limitation discovered during deep assembly and source code analysis.

**Severity Levels:**
- **CRITICAL**: Could cause crashes, data corruption, or security vulnerabilities
- **HIGH**: Performance degradation or reliability issues under load
- **MEDIUM**: Suboptimal patterns that may matter at extreme scale
- **LOW**: Minor inefficiencies or code quality concerns
- **INFO**: Architectural decisions with known tradeoffs

## SUMMARY

**Most Critical Issues to Address:**
1. Implement rate limiting (CLAUDE.md requirement)
2. Add SQ full recovery mechanism
3. Add stress/chaos testing
4. Document x86-TSO requirement explicitly
5. Add graceful shutdown with connection draining
