# Rule DSL: flux chains + webjail filters, not batch YAML/SQL

bandage's lineage (a batch SQL log analyzer's report model, flux's
trackers) makes that analyzer's rules file the obvious DSL. We
deliberately use flux-shaped chains with webjail's filter expression
language instead: bandage evaluates rules continuously over an event
stream, where trusted-SQL `where`/`having` clauses have no safe or
meaningful evaluation, and the chain/action model gives realtime control
flow (`goto`/`jump`/`stop`) that batch aggregate rules cannot express.

Considered options: batch-style YAML with SQL `where`/`having` (rejected:
trusted SQL cannot run safely in a long-lived stream evaluator; windowed
aggregates don't apply to leaky buckets); webjail filter syntax without
chains (rejected: no composition or dispatch between rule groups).
