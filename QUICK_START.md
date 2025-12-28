# SafeVault - Quick Start Guide

## Prerequisites
- .NET 10.0 SDK or later
- MySQL Server (8.0 or later recommended)
- Visual Studio Code or Visual Studio 2022

## Setup Instructions

### 1. Database Setup

#### Create Database
```sql
CREATE DATABASE SafeVaultDB;
USE SafeVaultDB;
```

#### Run Schema Script
Execute the SQL schema located at: `SafeVault/database.sql`

```powershell
# Using MySQL command line
mysql -u root -p SafeVaultDB < SafeVault\database.sql
```

### 2. Configure Connection String

Edit `SafeVaultAPI/appsettings.json`:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=SafeVaultDB;User=root;Password=YOUR_PASSWORD_HERE;"
  }
}
```

**Important**: Replace `YOUR_PASSWORD_HERE` with your actual MySQL password.

### 3. Run the Application

#### Terminal 1: Start the API
```powershell
cd SafeVaultAPI
dotnet run
```

The API will start at: `https://localhost:5001` (or the port shown in console)

#### Terminal 2: Start the Blazor App (Optional)
```powershell
cd SafeVault
dotnet run
```

### 4. Test the API

#### Using Swagger UI
Navigate to: `https://localhost:5001/swagger`

#### Using PowerShell
```powershell
# Test creating a user
$body = @{
    username = "testuser123"
    email = "test@example.com"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://localhost:5001/api/users" `
    -Method Post `
    -Body $body `
    -ContentType "application/json"
```

### 5. Run Security Tests

```powershell
cd SafeVaultTests
dotnet test --logger "console;verbosity=normal"
```

Expected output: **46 tests passed, 0 failed**

## Testing the Web Form

### Static HTML Form
Open in browser: `SafeVault/wwwroot/webform.html`

This demonstrates client-side validation with JavaScript.

### Blazor Component
If running the Blazor app, navigate to: `/userform`

## API Endpoints

### Create User
```http
POST /api/users
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com"
}
```

**Response (200 OK)**:
```json
{
  "userId": 1,
  "username": "john_doe",
  "email": "john@example.com"
}
```

### Get User by ID
```http
GET /api/users/{id}
```

**Response (200 OK)**:
```json
{
  "userID": 1,
  "username": "john_doe",
  "email": "john@example.com",
  "createdAt": "2025-12-28T10:30:00",
  "updatedAt": "2025-12-28T10:30:00"
}
```

### Update User Email
```http
PUT /api/users/{id}/email
Content-Type: application/json

{
  "newEmail": "newemail@example.com"
}
```

## Testing Security Features

### Test SQL Injection Prevention

Try creating a user with malicious input:

```powershell
$maliciousInput = @{
    username = "admin' OR '1'='1"
    email = "test@example.com"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://localhost:5001/api/users" `
    -Method Post `
    -Body $maliciousInput `
    -ContentType "application/json"
```

**Expected Result**: 
```json
{
  "error": "Username contains invalid characters"
}
```

### Test XSS Prevention

```powershell
$xssInput = @{
    username = "<script>alert('XSS')</script>"
    email = "test@example.com"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://localhost:5001/api/users" `
    -Method Post `
    -Body $xssInput `
    -ContentType "application/json"
```

**Expected Result**: 
```json
{
  "error": "Username contains invalid characters"
}
```

### Test Valid Input

```powershell
$validInput = @{
    username = "valid_user_123"
    email = "user@example.com"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://localhost:5001/api/users" `
    -Method Post `
    -Body $validInput `
    -ContentType "application/json"
```

**Expected Result**: User created successfully with status 200

## Validation Rules

### Username
- ✅ Length: 3-100 characters
- ✅ Characters: Letters, numbers, underscore only
- ✅ Pattern: `^[a-zA-Z0-9_]+$`
- ❌ No special characters
- ❌ No SQL keywords
- ❌ No script tags

### Email
- ✅ Valid email format
- ✅ Maximum 100 characters
- ✅ Pattern: `^[^@\s]+@[^@\s]+\.[^@\s]+$`
- ❌ No script tags
- ❌ No special characters

## Troubleshooting

### Database Connection Issues
1. Verify MySQL is running: `mysql --version`
2. Check connection string in `appsettings.json`
3. Ensure user has permissions: `GRANT ALL PRIVILEGES ON SafeVaultDB.* TO 'root'@'localhost';`

### Port Already in Use
If port 5001 is in use, modify `SafeVaultAPI/Properties/launchSettings.json`:
```json
{
  "applicationUrl": "https://localhost:5002;http://localhost:5003"
}
```

### Test Failures
Run tests with detailed output:
```powershell
dotnet test --logger "console;verbosity=detailed"
```

## Project Structure

```
SafeVault/
├── Pages/
│   └── UserForm.razor          # Blazor form component
├── wwwroot/
│   └── webform.html            # Static HTML form
├── database.sql                # Database schema
└── README.md                   # Full documentation

SafeVaultAPI/
├── Controllers/
│   └── UsersController.cs      # API endpoints
├── Services/
│   ├── InputValidationService.cs    # Input validation & sanitization
│   └── DatabaseService.cs           # Database operations
├── Program.cs                  # API configuration
└── appsettings.json           # Configuration

SafeVaultTests/
├── Tests/
│   ├── TestInputValidation.cs      # Input validation tests
│   └── TestDatabaseSecurity.cs     # SQL injection tests
└── SafeVaultTests.csproj
```

## Next Steps

1. ✅ Review the [README.md](README.md) for detailed documentation
2. ✅ Check [SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md) for test details
3. ✅ Explore the code in `SafeVaultAPI/Services/` to understand the security implementations
4. ✅ Run the tests to see security in action
5. ✅ Try the API with various inputs to test validation

## Support

For issues or questions:
- Review the main README.md
- Check the test results documentation
- Examine the code comments in the services

---
*Last Updated: December 28, 2025*
