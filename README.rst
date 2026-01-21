
=========================================
Zango AllAuth - Authentication for Zango
=========================================

A multi-tenant aware fork of django-allauth, purpose-built for the **Zango**
Django framework. This package provides comprehensive authentication and
authorization capabilities designed to work seamlessly with Zango's
multi-tenant architecture.

**Zango** is an enterprise-ready Django framework that enables rapid development
of business applications with built-in multi-tenancy, security, and compliance
features. Learn more at `https://zango.dev <https://zango.dev>`_

**Zango AllAuth** extends django-allauth to provide:

- **Multi-tenant Authentication**: Isolated authentication contexts for each tenant
- **Role-based Access Control**: Seamless integration with Zango's role and permission system
- **Social & Enterprise Login**: Support for OAuth, OIDC, SAML 2.0, and more
- **Account Management**: Comprehensive user registration, verification, and account management
- **Enterprise Ready**: Built with security and compliance in mind

Resources
==========

**Zango**
  Home: https://zango.dev
  Documentation: https://zango.dev/docs
  GitHub: https://github.com/Healthlane-Technologies/Zango
  Discord: https://discord.com/invite/WHvVjU23e7

**Zango AllAuth**
  Source code: https://github.com/Healthlane-Technologies/django-allauth/tree/zango_allauth
  Bug Tracker: https://github.com/Healthlane-Technologies/django-allauth/issues

**Django AllAuth** (Original Project)
  Home page: https://allauth.org/
  Source code: https://codeberg.org/allauth/django-allauth
  Documentation: https://docs.allauth.org/en/latest/

.. end-welcome

Why Zango AllAuth?
===================

.. begin-rationale

**Zango AllAuth** is a specialized fork of django-allauth created to seamlessly
integrate with Zango's multi-tenant architecture and enterprise features.

Key motivations:

- **Multi-Tenant Support**: Zango runs multiple independent applications on a single
  server. Authentication must be tenant-aware, isolating user data and permissions
  by application instance.

- **Role-Based Access Control**: Zango provides built-in role and permission management.
  AllAuth needed adaptation to work within this system while maintaining per-user,
  per-role authentication contexts.

- **Enterprise Features**: Modern applications often require multiple authentication
  methods (local accounts, social login, enterprise SSO). Zango AllAuth provides
  a unified authentication layer supporting all scenarios out of the box.

- **Simplified Integration**: Rather than cobbling together separate authentication
  packages, Zango AllAuth integrates seamlessly with Zango's configuration,
  deployment, and permission systems.

By combining django-allauth's battle-tested authentication logic with Zango's
multi-tenant and role-based architecture, Zango AllAuth provides enterprise-ready
authentication for rapidly developed business applications.

.. end-rationale


Features
========

.. begin-features

**🏢 Multi-Tenant Authentication**
    Authentication contexts are isolated per tenant. Each Zango application
    maintains its own user database, roles, and permissions with complete data
    isolation.

**👥 Multiple Authentication Methods**
    Supports local authentication (username/email), social login via OAuth 2.0
    and OpenID Connect, SAML 2.0 for enterprise SSO, and custom authentication
    protocols.

**🔐 Role-Based Access Control**
    Seamless integration with Zango's role and permission system. Define fine-grained
    permissions at the application level with easy-to-use policy definitions.

**💼 Enterprise Ready**
    Built from the ground up for enterprise applications. Includes SAML 2.0 support,
    account enumeration prevention, rate limiting, and comprehensive security features.

**⚙️ Smart Configuration**
    Provider credentials can be managed via Django settings or the Zango App Panel
    admin interface. Configuration per-tenant allows different authentication providers
    for different applications on the same deployment.

**🔒 Security First**
    Built-in rate limiting, account enumeration prevention, email verification,
    and secure password management. Battle-tested since 2010 with contributions
    from commercial organizations.

**🧩 Extensible Architecture**
    The adapter pattern allows customization of authentication flows. Override
    adapters to inject custom logic at key points in the authentication process.

**📱 Progressive Enhancement**
    Support for modern authentication features including multi-factor authentication,
    social account linking, and email address verification across all authentication
    methods.


.. end-features
