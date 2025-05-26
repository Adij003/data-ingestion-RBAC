from sqlalchemy.orm import Query
from sqlalchemy import or_, func

def search_model_any_keyword(
    base_query: Query,
    model,
    search_fields: list[str],
    query: str
):
    """
    Extend a base query to filter rows case-insensitively based on any keyword
    appearing in any of the specified fields.
    """
    if not query:
        return base_query.distinct().all()

    keywords = query.lower().split()
    filters = []

    for keyword in keywords:
        term = f"%{keyword}%"
        filters.extend([
            func.lower(getattr(model, field)).like(term)
            for field in search_fields
            if hasattr(model, field)
        ])

    if not filters:
        return base_query.distinct().all()

    return base_query.filter(or_(*filters)).distinct().all()
