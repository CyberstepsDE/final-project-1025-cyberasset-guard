"""Authentication and role-based access control.

  permissions   roles -> permissions (RBAC matrix)
  passwords     scrypt hashing + password policy
  models        User, UserSession (server-side sessions)
  service       login / logout / sessions / user management
  dependencies  FastAPI dependencies: current user, permission checks
  routes        /auth/* (login, logout, me, password) and /users/* (admin)
"""
