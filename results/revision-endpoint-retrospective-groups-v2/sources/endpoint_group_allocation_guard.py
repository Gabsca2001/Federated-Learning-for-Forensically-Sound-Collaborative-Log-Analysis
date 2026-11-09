"""Allocation identities use actual memberships, never nominal RNG seeds."""
from coherent_gradient_protocol import digest


def allocation_identity(rows):
    memberships={c:sorted(r['window_id'] for r in rs) for c,rs in sorted(rows.items())}
    identifiers=[x for rs in memberships.values() for x in rs]
    if len(identifiers)!=len(set(identifiers)):
        raise ValueError('duplicated training occurrence in allocation')
    return dict(membership_sha256=digest(memberships),population_sha256=digest(sorted(identifiers)),
        population_size=len(identifiers),client_counts={c:len(rs) for c,rs in memberships.items()})


def require_unique_allocations(records):
    if not records:raise ValueError('empty allocation audit')
    values=list(records.values())
    if len({x['membership_sha256'] for x in values})!=len(values):
        raise ValueError('nominally different seeds produced duplicate allocation memberships')
    if len({(x['population_sha256'],x['population_size']) for x in values})!=1:
        raise ValueError('allocations do not share the declared training population')
    return records
