# User Service

## Overview
The **User Service** handles authentication, authorization, and user management for the Fullstack Medical Journaling System. It enforces **Spring Security** with **JWT-based authentication** and supports different user roles: **patients, doctors, and staff**.

## Features
- User registration and login
- Role-based authentication (Spring Security)
- JWT token generation and validation
- Secure API endpoints

## Technologies Used
- **Spring Boot**
- **Spring Security & JWT**
- **PostgreSQL/MySQL**
- **Docker & Kubernetes**

## Installation & Setup
```sh
git clone https://github.com/yourusername/user-service.git
cd user-service
mvn clean install
docker build -t user-service .
docker run -p 8081:8081 user-service
```


## Other Services
- Communicates with Patient Service for fetching user-related patient data.
- Works with Message Service for secure messaging.**
