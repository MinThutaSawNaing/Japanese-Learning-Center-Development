Han Nay Japanese Language Center
A modern Japanese learning platform with course management, payment integration, and real-time communication.

🚀 Features
Student Features:

N5 to N1 Japanese courses

KBZ Pay QR code payments

Interactive quizzes & progress tracking

Support system (technical & teacher Q&A)

Real-time notifications

Admin Features:

Dashboard for purchase approvals

User management & moderation

Message handling system

Admin account management

Live updates via Socket.IO

🛠 Tech Stack
Frontend: HTML5, CSS3, JavaScript

Real-time: Socket.IO

UI: Font Awesome, Google Fonts

Design: Responsive, mobile-first

📦 Quick Start
Setup Backend (required for full functionality)

File Structure:

text
project/
├── main.html
└── static/
    └── images/
        ├── icon.png
        ├── logohn.jpg
        ├── hero.jpg
        └── kpay.jpg
Backend Requirements:

User authentication (/login, /register)

Course management (/courses)

Payment processing (/purchase/{level})

Support system endpoints

Socket.IO event handlers

🎯 Usage
Students:

Register/Login → Browse Courses → Purchase via KBZ Pay → Access Materials

Admins:

Admin Login → Dashboard → Manage Purchases → Handle Messages

🔧 Key Endpoints
text
/auth          → Login, Register, Logout
/courses       → Course listings
/purchase      → Payment processing
/support       → Student inquiries
/admin/*       → Admin operations
/socket.io     → Real-time features
📱 Compatibility
Fully responsive design for:

Desktop

Tablet

Mobile
