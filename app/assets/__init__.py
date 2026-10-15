"""Asset Management — block 1 of the CyberAsset Guard design.

  models    SQLAlchemy entities (Asset, AssetTag) and controlled vocabularies
  schemas   Pydantic request / response schemas (API contract, separate from the DB model)
  service   business logic: create, list/search/filter, update, deactivate
  routes    REST API under /assets
"""
