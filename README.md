

# Japanese Learning Center

A Flask-based web application for managing Japanese language courses, user registrations, and online payments.

## Features

- User authentication (email/password and Google OAuth)
- Course purchasing system (N5-N1 levels)
- Support and teacher messaging
- Admin dashboard for managing users and purchases
- KBZ Pay payment integration

## Setup

### Local Development

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python app.py
   ```
4. Access at `http://localhost:7777`

### Docker Deployment

1. Build the image:
   ```bash
   docker build -t japan .
   ```
2. Run the container:
   ```bash
   docker run -p 7777:7777 japan
   ```
3. Access at `http://localhost:7777`

## Default Admin

- Email: `admin@example.com`
- Password: `admin123`

## Configuration

- Change `app.secret_key` in production
- Configure Google OAuth in `google_credentials.json`
- Update payment details in course content

## License

MIT License
