curl -X POST http://localhost:8080/auth/register \
-H "Content-Type: application/json" \
-d '{
    "email": "test@example.com",
    "password": "Password123!",
    "first_name": "John",
    "last_name": "Doe"
}'