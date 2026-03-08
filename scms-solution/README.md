# Student Course Management System (SCMS)

This project is a backend API for managing students, courses, and enrollments, built with Node.js, Express, and Supabase.

## 1. Setup Instructions

### Prerequisites
- Node.js installed
- Supabase account

### Installation
1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd scms-backend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Configure Environment Variables:
   - Rename `.env.example` to `.env`
   - Add your Supabase URL and Key:
     ```
     SUPABASE_URL=your_supabase_url
     SUPABASE_KEY=your_supabase_anon_key
     ```
4. Setup Database:
   - Go to Supabase SQL Editor.
   - Run the script from `schema.sql`.

### Running the Server
- Development: `npm run dev`
- Production: `npm start`

---

## 2. API Documentation

### Students
- `GET /api/students`: Get all students
- `GET /api/students/:id`: Get student by ID
- `POST /api/students`: Create new student
  - Body: `{ "fullname": "Name", "email": "email@test.com", "major": "CS" }`
- `PUT /api/students/:id`: Update student
- `DELETE /api/students/:id`: Delete student

### Courses
- `GET /api/courses`: Get all courses
- `POST /api/courses`: Create new course
  - Body: `{ "name": "Course Name", "description": "Desc", "credit": 3 }`

### Enrollments
- `POST /api/enrollments`: Enroll student in a course
  - Body: `{ "student_id": 1, "course_id": 1 }`
- `GET /api/enrollments/student/:studentId`: Get courses for a student

---

## 3. Exam Explanations

### Database Design
- **PK/FK**: Primary Keys (id) uniquely identify records. Foreign Keys (student_id, course_id) link enrollments to specific students and courses, ensuring data integrity.
- **Normalization**: The database is in 3NF. We separated Students and Courses into their own tables to avoid duplication. The Enrollments table acts as a junction table for the Many-to-Many relationship.

### API Design
- **Router**: We use `express.Router()` to modularize code. `routes/students.js` handles all student-related logic, keeping `server.js` clean.
- **RESTful Principles**:
  - **Resources**: URLs represent resources (e.g., `/students`).
  - **HTTP Methods**: Use standard methods (GET for reading, POST for creating, PUT for updating, DELETE for removing).
  - **Stateless**: Each request contains all necessary info; the server doesn't store client state between requests.

### Git Workflow
1. **Main Branch**: Contains production-ready code.
2. **Feature Branches**: Create a new branch for each feature (e.g., `feature/add-student-api`).
3. **Commit**: Make small, descriptive commits.
4. **Merge Request (PR)**: Review code before merging into main.

### Deployment (Render)
**Steps:**
1. Push code to GitHub.
2. Connect Render to GitHub repository.
3. Select "Web Service".
4. Set Build Command: `npm install`
5. Set Start Command: `node server.js`
6. Add Environment Variables (SUPABASE_URL, SUPABASE_KEY) in Render Dashboard.

**Cloud Deployment Pros/Cons:**
- **Pros**: Scalability, Accessibility (public URL), No hardware maintenance, CI/CD integration.
- **Cons**: Cost (if scaling up), Internet dependency, Potential security risks if not configured correctly.
