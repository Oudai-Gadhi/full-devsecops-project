# Insurance Accident Declaration Web Application

 A full-stack solution for digital insurance accident declarations, built with FastAPI (Python), React (TypeScript), and MySQL.

##Features
- **Client Declaration Form**: Submit personal info, vehicle details, and accident reports.
- **File Uploads**: Supports PDF, PNG, and JPG attachments.
- **Admin Dashboard**: Insurance agents can review claims, download attachments, and update status.
- **Responsive UI**: Modern design with Tailwind CSS.
- **Dockerized**: Easy setup with Docker Compose.

##Prerequisites
- **Docker** and **Docker Compose** installed.
- Ensure your user is in the `docker` group or use `sudo`.

## How to Run (Linux)

1. **Navigate to the directory**:
   ```bash
   cd /home/oudai/insurance_app
   ```

2. **Set permissions for the uploads folder** (to ensure the container can write to it):
   ```bash
   chmod -R 777 backend/uploads
   ```

3. **Spin up the containers**:
   ```bash
   sudo docker-compose up --build -d
   ```
   *-d runs it in detached mode. Remove it if you want to see logs.*

4. **Verify containers are running**:
   ```bash
   sudo docker-compose ps
   ```

5. **Access the Application**:
   - **Client Form**: [http://localhost:5173](http://localhost:5173)
   - **Admin Dashboard**: [http://localhost:5173/admin](http://localhost:5173/admin)
   - **API Documentation (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)

## Tech Stack Details
- **Frontend**: React 18, Vite, Tailwind CSS, Lucide Icons, Axios.
- **Backend**: FastAPI, SQLAlchemy (ORM), Pymysql.
- **Database**: MySQL 8.0.
- **Orchestration**: Docker Compose.

## Directory Structure
- `/backend`: FastAPI application and file uploads storage.
- `/frontend`: React application source code.
- `docker-compose.yml`: Orchestration config.
- `.env`: Database credentials and environment variables.

##Notes
- Uploaded files are stored in `backend/uploads`. In the Docker version, these are mapped to a volume to persist data.
- The MySQL database data is persisted in a Docker volume named `mysql_data`.
