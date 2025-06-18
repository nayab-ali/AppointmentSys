# AppointmentSys - Student-Teacher Booking System

## Overview

AppointmentSys is a web application built with Python Flask to facilitate scheduling between students and teachers. It features role-based access (Admin, Teacher, Student), appointment booking, a contact form with email notifications, and downloadable appointment summaries.

## Features

- Responsive multi-page design (Home, About, Contact, Dashboards).
- Role-based login for Admin, Teacher, and Student.
- Appointment booking with slot management by teachers.
- Contact form with email integration using Flask-Mail.
- Admin controls for managing users and appointments.
- Downloadable appointment summaries.

## Tech Stack

- **Frontend**: HTML, CSS, Jinja2
- **Backend**: Python, Flask
- **Database**: MySQL

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/nayab-ali/AppointmentSys.git
   cd AppointmentSys
   ```

2. **Set Up Environment**

   - Create a virtual environment and install dependencies:

     ```bash
     python -m venv venv
     source venv/bin/activate  # On Windows: venv\Scripts\activate
     pip install -r requirements.txt
     ```

   - Create a `.env` file with the following (replace with your details):

     ```
     FLASK_APP=app.py
     FLASK_ENV=development
     SECRET_KEY=your_secret_key_here
     MYSQL_HOST=your-mysql-host
     MYSQL_USER=your-mysql-username
     MYSQL_PASSWORD=your-mysql-password
     MYSQL_DB=your-mysql-dbname
     ```

3. **Database Setup**

   - Set up a local MySQL database and create the required tables (refer to the LLD document).
   - Update `app.py` with your MySQL connection details.

4. **Run Locally**

   ```bash
   flask run
   ```

   Visit `http://localhost:5000` to test the application.

## Usage

- **Home**: View the main page with appointment options.
- **Login/Register**: Access role-specific dashboards.
- **Contact**: Submit queries emailed to the admin.
- **Booking**: Students book slots, and teachers approve/cancel them.

## Contributing

- Fork the repository and create a new branch.
- Commit changes and submit a pull request.

## License

No license, All right reserved.

## Contact

For questions, email `nayabmca2024@gmail.com` or open an issue on GitHub.