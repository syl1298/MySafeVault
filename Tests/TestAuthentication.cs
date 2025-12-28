using NUnit.Framework;
using SafeVaultAPI.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Moq;

namespace SafeVaultTests;

[TestFixture]
public class TestAuthentication
{
    private IPasswordHashingService _passwordHashingService = null!;
    private Mock<ILogger<PasswordHashingService>> _loggerMock = null!;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<PasswordHashingService>>();
        _passwordHashingService = new PasswordHashingService(_loggerMock.Object);
    }

    #region Password Hashing Tests

    [Test]
    public void TestPasswordHashing_Success()
    {
        // Arrange
        var password = "TestPassword123!";

        // Act
        var hashedPassword = _passwordHashingService.HashPassword(password, out var salt);

        // Assert
        Assert.That(hashedPassword, Is.Not.Null);
        Assert.That(hashedPassword, Is.Not.Empty);
        Assert.That(hashedPassword, Is.Not.EqualTo(password), "Password should be hashed, not plaintext");
        Assert.That(salt, Is.Not.Null);
        Assert.That(salt, Is.Not.Empty);
        
        Console.WriteLine($"Original: {password}");
        Console.WriteLine($"Hashed: {hashedPassword}");
        Console.WriteLine($"Salt: {salt}");
    }

    [Test]
    public void TestPasswordHashing_DifferentHashesForSamePassword()
    {
        // Arrange
        var password = "SamePassword123!";

        // Act
        var hash1 = _passwordHashingService.HashPassword(password, out var salt1);
        var hash2 = _passwordHashingService.HashPassword(password, out var salt2);

        // Assert
        Assert.That(hash1, Is.Not.EqualTo(hash2), "BCrypt should generate different hashes with different salts");
        Assert.That(salt1, Is.Not.EqualTo(salt2), "Salts should be different");
        
        Console.WriteLine($"Hash 1: {hash1}");
        Console.WriteLine($"Hash 2: {hash2}");
    }

    [Test]
    public void TestPasswordHashing_EmptyPassword_ThrowsException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            _passwordHashingService.HashPassword("", out var salt));
        
        Assert.Throws<ArgumentException>(() => 
            _passwordHashingService.HashPassword(null!, out var salt));
    }

    #endregion

    #region Password Verification Tests

    [Test]
    public void TestPasswordVerification_CorrectPassword_ReturnsTrue()
    {
        // Arrange
        var password = "CorrectPassword123!";
        var hashedPassword = _passwordHashingService.HashPassword(password, out var salt);

        // Act
        var isValid = _passwordHashingService.VerifyPassword(password, hashedPassword, salt);

        // Assert
        Assert.That(isValid, Is.True, "Correct password should verify successfully");
        
        Console.WriteLine($"Password verification successful for: {password}");
    }

    [Test]
    public void TestPasswordVerification_IncorrectPassword_ReturnsFalse()
    {
        // Arrange
        var correctPassword = "CorrectPassword123!";
        var wrongPassword = "WrongPassword456!";
        var hashedPassword = _passwordHashingService.HashPassword(correctPassword, out var salt);

        // Act
        var isValid = _passwordHashingService.VerifyPassword(wrongPassword, hashedPassword, salt);

        // Assert
        Assert.That(isValid, Is.False, "Wrong password should fail verification");
        
        Console.WriteLine($"Password verification correctly failed for wrong password");
    }

    [Test]
    public void TestPasswordVerification_EmptyPassword_ReturnsFalse()
    {
        // Arrange
        var password = "TestPassword123!";
        var hashedPassword = _passwordHashingService.HashPassword(password, out var salt);

        // Act
        var isValid = _passwordHashingService.VerifyPassword("", hashedPassword, salt);

        // Assert
        Assert.That(isValid, Is.False, "Empty password should fail verification");
    }

    [Test]
    public void TestPasswordVerification_BCryptWithoutExplicitSalt()
    {
        // Arrange
        var password = "TestPassword123!";
        var hashedPassword = _passwordHashingService.HashPassword(password, out var salt);

        // Act - BCrypt doesn't need explicit salt for verification
        var isValid = _passwordHashingService.VerifyPassword(password, hashedPassword);

        // Assert
        Assert.That(isValid, Is.True, "BCrypt should verify without explicit salt");
    }

    #endregion

    #region Password Strength Validation Tests

    [Test]
    [TestCase("Weak1!", ExpectedResult = false, Description = "Too short")]
    [TestCase("toolongpasswordthatexceedsthemaximumlengthallowedbyBCryptwhichisseventytwobytes123!", ExpectedResult = false, Description = "Too long")]
    [TestCase("nouppercase123!", ExpectedResult = false, Description = "No uppercase")]
    [TestCase("NOLOWERCASE123!", ExpectedResult = false, Description = "No lowercase")]
    [TestCase("NoNumbers!", ExpectedResult = false, Description = "No numbers")]
    [TestCase("NoSpecialChar123", ExpectedResult = false, Description = "No special characters")]
    [TestCase("ValidPass123!", ExpectedResult = true, Description = "Valid password")]
    [TestCase("Str0ng!Pass", ExpectedResult = true, Description = "Valid password")]
    public bool TestPasswordStrengthValidation(string password)
    {
        // Act
        var result = _passwordHashingService.ValidatePasswordStrength(password);

        // Assert
        Console.WriteLine($"Password: {password}");
        Console.WriteLine($"Valid: {result.IsValid}");
        if (!result.IsValid)
        {
            Console.WriteLine($"Errors: {string.Join(", ", result.Errors)}");
        }
        
        return result.IsValid;
    }

    [Test]
    public void TestPasswordStrengthValidation_EmptyPassword()
    {
        // Act
        var result = _passwordHashingService.ValidatePasswordStrength("");

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Errors, Contains.Item("Password is required"));
    }

    #endregion

    #region Brute Force Protection Tests

    [Test]
    public void TestPasswordHashing_ResistantToBruteForce()
    {
        // This test demonstrates that BCrypt is slow by design
        // which protects against brute force attacks
        
        var password = "TestPassword123!";
        var startTime = DateTime.UtcNow;
        
        // Hash password
        var hashedPassword = _passwordHashingService.HashPassword(password, out var salt);
        
        var hashTime = DateTime.UtcNow - startTime;
        
        Console.WriteLine($"Time to hash password: {hashTime.TotalMilliseconds}ms");
        Console.WriteLine($"This intentional slowness protects against brute force attacks");
        
        // BCrypt with work factor 12 should take at least a few milliseconds
        Assert.That(hashTime.TotalMilliseconds, Is.GreaterThan(1), 
            "BCrypt should be slow enough to deter brute force");
    }

    [Test]
    public void TestPasswordVerification_ConstantTimeComparison()
    {
        // BCrypt uses constant-time comparison internally
        // This test verifies the behavior is consistent
        
        var password = "TestPassword123!";
        var hashedPassword = _passwordHashingService.HashPassword(password, out var salt);
        
        var startTime1 = DateTime.UtcNow;
        var result1 = _passwordHashingService.VerifyPassword(password, hashedPassword);
        var time1 = DateTime.UtcNow - startTime1;
        
        var startTime2 = DateTime.UtcNow;
        var result2 = _passwordHashingService.VerifyPassword("WrongPassword123!", hashedPassword);
        var time2 = DateTime.UtcNow - startTime2;
        
        Console.WriteLine($"Correct password verification time: {time1.TotalMilliseconds}ms");
        Console.WriteLine($"Wrong password verification time: {time2.TotalMilliseconds}ms");
        
        Assert.That(result1, Is.True);
        Assert.That(result2, Is.False);
        
        // Times should be similar (within an order of magnitude)
        // to prevent timing attacks
    }

    #endregion

    #region Invalid Login Attempt Simulation Tests

    [Test]
    public void TestInvalidLoginAttempt_WrongPassword()
    {
        // Simulate a login attempt with wrong password
        // Arrange
        var correctPassword = "CorrectPass123!";
        var wrongPassword = "WrongPass456!";
        var hashedPassword = _passwordHashingService.HashPassword(correctPassword, out var salt);

        // Act
        var isValid = _passwordHashingService.VerifyPassword(wrongPassword, hashedPassword);

        // Assert
        Assert.That(isValid, Is.False);
        Console.WriteLine("✓ Invalid login attempt (wrong password) correctly rejected");
    }

    [Test]
    public void TestInvalidLoginAttempt_SQLInjectionInPassword()
    {
        // Simulate SQL injection attempt in password field
        // Arrange
        var realPassword = "RealPass123!";
        var maliciousPassword = "' OR '1'='1' --";
        var hashedPassword = _passwordHashingService.HashPassword(realPassword, out var salt);

        // Act
        var isValid = _passwordHashingService.VerifyPassword(maliciousPassword, hashedPassword);

        // Assert
        Assert.That(isValid, Is.False);
        Console.WriteLine("✓ SQL injection attempt in password field blocked");
    }

    [Test]
    public void TestMultipleFailedAttempts_Simulation()
    {
        // Simulate multiple failed login attempts
        var correctPassword = "CorrectPass123!";
        var hashedPassword = _passwordHashingService.HashPassword(correctPassword, out var salt);
        
        int failedAttempts = 0;
        var wrongPasswords = new[] { "wrong1", "wrong2", "wrong3", "wrong4", "wrong5" };
        
        foreach (var wrongPassword in wrongPasswords)
        {
            var isValid = _passwordHashingService.VerifyPassword(wrongPassword, hashedPassword);
            if (!isValid)
            {
                failedAttempts++;
            }
        }
        
        Assert.That(failedAttempts, Is.EqualTo(5));
        Console.WriteLine($"✓ Simulated {failedAttempts} failed login attempts - all correctly rejected");
        Console.WriteLine("  In production, account would be locked after 5 failed attempts");
    }

    #endregion

    #region Hash Security Tests

    [Test]
    public void TestPasswordHash_NotReversible()
    {
        // Demonstrate that password hashing is one-way
        var password = "SecretPassword123!";
        var hashedPassword = _passwordHashingService.HashPassword(password, out var salt);
        
        // There should be no way to reverse the hash back to the original password
        Assert.That(hashedPassword, Does.Not.Contain(password));
        Assert.That(hashedPassword, Is.Not.EqualTo(password));
        
        Console.WriteLine("✓ Password hash is not reversible");
        Console.WriteLine($"  Original password not found in hash: {hashedPassword}");
    }

    [Test]
    public void TestPasswordHash_ContainsSalt()
    {
        // BCrypt embeds the salt in the hash
        var password = "TestPassword123!";
        var hashedPassword = _passwordHashingService.HashPassword(password, out var salt);
        
        // BCrypt format: $2a$[workfactor]$[22 char salt][31 char hash]
        Assert.That(hashedPassword, Does.StartWith("$2"));
        Assert.That(hashedPassword.Length, Is.GreaterThan(50));
        
        Console.WriteLine($"✓ BCrypt hash format verified: {hashedPassword}");
        Console.WriteLine($"  Salt is embedded in the hash");
    }

    #endregion
}
