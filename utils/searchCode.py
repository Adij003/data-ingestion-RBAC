from sqlalchemy.orm import Session
from sqlalchemy import or_, func

def search_model_any_keyword(
    db: Session,
    model,
    search_fields: list[str],
    query: str
):
    """
    Search case-insensitively for any keyword in the query string
    across multiple fields. Returns unique rows.
    """
    if not query:
        return db.query(model).all()

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
        return []

    return db.query(model).filter(or_(*filters)).distinct().all()
