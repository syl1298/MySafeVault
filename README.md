# SafeVault - Secure Web Application

## Overview
SafeVault is a secure web application demonstrating best practices for input validation, SQL injection prevention, and XSS protection.

## Project Structure

### SafeVault (Blazor WebAssembly)
- Client-side web application with input validation
- User registration form with real-time validation
- Located in: `SafeVault/`

### SafeVaultAPI (ASP.NET Core Web API)
- Backend API with secure database operations
- Input validation and sanitization services
- Parameterized queries for SQL injection prevention
- Audit logging for security monitoring
- Located in: `SafeVaultAPI/`

### SafeVaultTests (NUnit Test Project)
- Comprehensive security tests
- SQL injection prevention tests
- XSS (Cross-Site Scripting) prevention tests
- Input validation tests
- Located in: `SafeVaultTests/`

## Security Features

### 1. Input Validation
- **Client-side validation**: HTML5 and JavaScript validation in web forms
- **Server-side validation**: `InputValidationService` validates all inputs
- **Sanitization**: Removes dangerous characters (<, >, ', ", ;, etc.)
- **Format validation**: Regex patterns for username and email

### 2. SQL Injection Prevention
- **Parameterized queries**: All database queries use `@Parameters`
- **No string concatenation**: Never build SQL with user input
- **Type safety**: Parameters are strongly typed
- **Example**:
  ```csharp
  // SECURE - Uses parameterized query
  var query = "SELECT * FROM Users WHERE Username = @Username";
  command.Parameters.AddWithValue("@Username", username);
  
  // INSECURE - DO NOT USE
  var query = "SELECT * FROM Users WHERE Username = '" + username + "'";
  ```

### 3. XSS Prevention
- **Input sanitization**: Removes HTML tags and script keywords
- **Output encoding**: Data is properly encoded when displayed
- **Content Security Policy**: Can be configured in production

### 4. Defense in Depth
Multiple layers of security:
1. Client-side validation (HTML5, JavaScript)
2. Server-side input validation
3. Input sanitization
4. Parameterized queries
5. Database constraints
6. Audit logging

## Database Setup

### Create Database
```sql
CREATE DATABASE SafeVaultDB;
USE SafeVaultDB;
```

### Run Schema
Execute the SQL file: `SafeVault/database.sql`

### Configure Connection String
Update `SafeVaultAPI/appsettings.json`:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=SafeVaultDB;User=root;Password=yourpassword;"
  }
}
```

## Running the Application

### 1. Run the API
```powershell
cd SafeVaultAPI
dotnet run
```
API will be available at: `https://localhost:5001` (or configured port)

### 2. Run the Blazor App
```powershell
cd SafeVault
dotnet run
```
App will be available at: `https://localhost:5001` (or configured port)

### 3. Run Tests
```powershell
cd SafeVaultTests
dotnet test
```

## Testing Security

### SQL Injection Tests
The test suite includes tests for common SQL injection patterns:
- `admin' OR '1'='1`
- `'; DROP TABLE Users; --`
- `admin'; UPDATE Users SET IsAdmin=1; --`

All these attacks are prevented by:
1. Input sanitization (removes dangerous characters)
2. Parameterized queries (treats input as data, not code)

### XSS Tests
Tests for cross-site scripting vulnerabilities:
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `javascript:alert('XSS')`

All these attacks are prevented by:
1. Input sanitization (removes HTML tags)
2. Character filtering (removes <, >, script, javascript)

## API Endpoints

### POST /api/users
Create a new user
```json
{
  "username": "john_doe",
  "email": "john@example.com"
}
```

### GET /api/users/{id}
Retrieve user by ID

### PUT /api/users/{id}/email
Update user email
```json
{
  "newEmail": "newemail@example.com"
}
```

## Validation Rules

### Username
- Length: 3-100 characters
- Allowed characters: Letters, numbers, underscore
- Pattern: `^[a-zA-Z0-9_]+$`

### Email
- Maximum length: 100 characters
- Must be valid email format
- Pattern: `^[^@\s]+@[^@\s]+\.[^@\s]+$`

## Security Best Practices Implemented

1. ✅ **Input Validation**: All inputs validated before processing
2. ✅ **Input Sanitization**: Dangerous characters removed
3. ✅ **Parameterized Queries**: SQL injection prevention
4. ✅ **XSS Prevention**: Script tags and HTML removed
5. ✅ **Audit Logging**: All operations logged with IP and timestamp
6. ✅ **Error Handling**: Errors logged, sensitive info not exposed
7. ✅ **Least Privilege**: Database user has minimum permissions
8. ✅ **No Dynamic SQL**: Queries are predefined, not built from input

## Test Results

Run the tests to verify security:
```powershell
cd SafeVaultTests
dotnet test --logger "console;verbosity=detailed"
```

Expected results:
- ✅ SQL injection attempts blocked
- ✅ XSS attempts sanitized
- ✅ Valid inputs accepted
- ✅ Parameterized queries used throughout

## Production Considerations

Before deploying to production:

1. **Use HTTPS**: Enforce HTTPS for all communications
2. **Strong Passwords**: Use strong database passwords
3. **Rate Limiting**: Implement rate limiting on API endpoints
4. **CORS**: Configure CORS properly for production domains
5. **Logging**: Set up centralized logging (e.g., Serilog, Application Insights)
6. **Monitoring**: Monitor for unusual patterns in audit logs
7. **Database**: Use connection pooling and proper indexes
8. **Secrets**: Store connection strings in Azure Key Vault or similar

## License
This is a demonstration project for educational purposes.
