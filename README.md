# progTek-pwm Password Manager

progTek-pwm is an open-source password manager built with Python, offering strong security and end-to-end encryption. This project consists of a server component (this repository) and a client application [progTek-pwm-Client](https://github.com/pkimSec/progTek-pwm-Client).

## Features

- **End-to-End Encryption**: Your passwords are encrypted before leaving your device
- **Zero-Knowledge Architecture**: The server never has access to your unencrypted passwords
- **Version History**: Track changes to your password entries
- **Role-Based Access Control**: Admin and regular user roles
- **Invite-Only Registration**: Control who can join your password manager instance
- **Rate Limiting**: Protection against brute force attacks
- **Secure Headers**: Implementation of modern web security headers
- **REST API**: Well-documented API for potential custom clients

## Security Features

- **Client-Side Encryption**: All sensitive data is encrypted/decrypted locally on the client
- **AES-GCM Encryption**: Industry-standard encryption for password data
- **PBKDF2 Key Derivation**: Secure key derivation from master password
- **Password-Based Authentication**: Securely hashed passwords using Werkzeug
- **JWT Authentication**: Token-based authentication with limited lifetime
- **Secure HTTP Headers**: Protection against common web vulnerabilities
- **Session Management**: Secure session handling with timeout
- **HTTPS Enforcement**: API can be configured to require HTTPS

## Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager
- SQLite or another database supported by SQLAlchemy (for production)

### Server Setup

1. Clone the repository:
   ```
   git clone https://github.com/pkimSec/progTek-pwm-Server.git
   cd progTek-pwm-Server
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Configure the application (optional):
   - Edit `server/config.py` to change default settings
   - Set environment variables to override configuration:
     - `SECRET_KEY`: Flask secret key
     - `JWT_SECRET_KEY`: Secret for JWT tokens
     - `SQLALCHEMY_DATABASE_URI`: Database connection string

5. Run the server:
   ```
   python run.py
   ```
   
   The server will start on `localhost:5000` by default.
   
   On first run, an admin account will be created with the credentials displayed in the console.

## Usage

The server provides a REST API for the client application. To use the password manager:

1. Install the client application from the [progTek-pwm-Client](https://github.com/pkimSec/progTek-pwm-Client) repository
2. Connect the client to your running server instance
3. Log in with the admin credentials then register a new account using an invite code

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/login` | POST | Authenticate user and get access token |
| `/api/logout` | POST | Invalidate session |
| `/api/register` | POST | Register new user with invite code |
| `/api/invite` | POST | Create invite code (admin only) |
| `/api/vault/entries` | GET | List all password entries |
| `/api/vault/entries` | POST | Create new password entry |
| `/api/vault/entries/<id>` | GET | Get specific password entry |
| `/api/vault/entries/<id>` | PUT | Update password entry |
| `/api/vault/entries/<id>` | DELETE | Delete password entry |
| `/api/vault/entries/<id>/versions` | GET | List entry versions |

For a complete API reference, see the API documentation (coming soon).

## Development

### Project Structure

```
progTek-pwm-Server/
├── server/              # Server code
│   ├── __init__.py
│   ├── app.py           # Flask application factory
│   ├── config.py        # Configuration
│   ├── crypto.py        # Encryption utilities
│   ├── limiter.py       # Rate limiting
│   ├── models.py        # Database models
│   ├── routes.py        # Authentication routes
│   ├── security.py      # Security headers
│   ├── session.py       # Session management
│   └── vault_routes.py  # Password vault routes
├── tests/               # Test suite
├── .gitignore
├── LICENSE             # GNU GPL v3
├── README.md
├── requirements.txt
├── run.py              # Server entry point
└── setup.py
```

### Running Tests

```
pytest
```

For test coverage report:

```
pytest --cov=server tests/
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

### Development Guidelines

1. Follow PEP 8 style guidelines
2. Write unit tests for new features
3. Update documentation for API changes
4. Run the test suite before submitting PRs

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Roadmap

- [ ] Two-factor authentication
- [ ] Password sharing functionality
- [ ] Import/export feature
- [ ] Audit log for security events
- [ ] Docker containerization
- [ ] Backup and restore functionality

## Acknowledgments

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM
- [PyJWT](https://pyjwt.readthedocs.io/) - JWT implementation
- [Cryptography](https://cryptography.io/) - Cryptographic primitives