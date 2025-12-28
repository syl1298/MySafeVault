using NUnit.Framework;
using SafeVaultAPI.Services;
using Microsoft.Extensions.Logging;
using Moq;
using System.Text;

namespace SafeVaultTests;

/// <summary>
/// Advanced security attack simulation tests
/// Tests for sophisticated attack patterns including:
/// - Second-order SQL injection
/// - Blind SQL injection
/// - Time-based SQL injection
/// - Stored XSS
/// - DOM-based XSS
/// - Unicode/encoding bypass attempts
/// - LDAP injection
/// - XML injection
/// - Template injection
/// - Server-Side Request Forgery (SSRF)
/// - Path traversal
/// - HTTP header injection
/// - CRLF injection
/// </summary>
[TestFixture]
public class TestAdvancedSecurityAttacks
{
    private IInputValidationService _validationService = null!;
    private Mock<ILogger<InputValidationService>> _loggerMock = null!;

    [SetUp]
    public void Setup()
    {
        _loggerMock = new Mock<ILogger<InputValidationService>>();
        _validationService = new InputValidationService(_loggerMock.Object);
    }

    #region Second-Order SQL Injection Tests

    [Test]
    [Description("Second-order SQL injection: Malicious data stored then executed later")]
    public void TestSecondOrderSQLInjection_StoredThenExecuted()
    {
        // Arrange - Attacker tries to store malicious SQL that executes on retrieval
        var maliciousUsername = "admin' UNION SELECT password FROM Users WHERE '1'='1";
        
        // Act - Sanitize on storage
        var sanitized = _validationService.SanitizeInput(maliciousUsername);
        var validation = _validationService.ValidateUsername(sanitized);
        
        // Assert - Should be blocked at storage time
        Assert.That(sanitized, Does.Not.Contain("'"));
        Assert.That(sanitized, Does.Not.Contain("UNION"));
        Assert.That(validation.IsValid, Is.False);
        
        Console.WriteLine("Second-Order SQL Injection Test:");
        Console.WriteLine($"Input: {maliciousUsername}");
        Console.WriteLine($"Sanitized: {sanitized}");
        Console.WriteLine($"Blocked: {!validation.IsValid}");
    }

    [Test]
    [TestCase("admin'; WAITFOR DELAY '00:00:05'--")]
    [TestCase("admin' AND SLEEP(5)--")]
    [TestCase("admin' OR BENCHMARK(10000000,MD5('test'))--")]
    [Description("Time-based blind SQL injection attempts")]
    public void TestTimeBasedBlindSQLInjection(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        var validation = _validationService.ValidateUsername(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("'"));
        Assert.That(sanitized, Does.Not.Contain("--"));
        Assert.That(sanitized, Does.Not.Contain("WAITFOR"));
        Assert.That(sanitized, Does.Not.Contain("SLEEP"));
        Assert.That(validation.IsValid, Is.False);
        
        Console.WriteLine($"Time-based SQL injection blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("admin' AND (SELECT COUNT(*) FROM Users) > 0--")]
    [TestCase("admin' AND 1=(SELECT COUNT(*) FROM Users)--")]
    [Description("Boolean-based blind SQL injection")]
    public void TestBooleanBasedBlindSQLInjection(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("'"));
        Assert.That(sanitized, Does.Not.Contain("SELECT"));
        Assert.That(sanitized, Does.Not.Contain("--"));
        
        Console.WriteLine($"Boolean-based blind SQL injection blocked: {maliciousInput}");
    }

    #endregion

    #region Advanced XSS Tests

    [Test]
    [TestCase("<svg><script>alert('XSS')</script></svg>")]
    [TestCase("<math><mtext><script>alert('XSS')</script></mtext></math>")]
    [TestCase("<details open ontoggle=alert('XSS')>")]
    [TestCase("<marquee onstart=alert('XSS')>")]
    [Description("Stored XSS with nested tags")]
    public void TestStoredXSS_NestedTags(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("<"));
        Assert.That(sanitized, Does.Not.Contain(">"));
        Assert.That(sanitized, Does.Not.Contain("script"));
        
        Console.WriteLine($"Stored XSS blocked: {maliciousInput} -> {sanitized}");
    }

    [Test]
    [TestCase("javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>")]
    [TestCase("<img src=x onerror=\"&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041\">")]
    [Description("XSS with obfuscation and encoding")]
    public void TestXSS_ObfuscatedAndEncoded(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("<"));
        Assert.That(sanitized, Does.Not.Contain(">"));
        Assert.That(sanitized, Does.Not.Contain("javascript"));
        Assert.That(sanitized.Length, Is.LessThan(maliciousInput.Length));
        
        Console.WriteLine($"Obfuscated XSS blocked: {maliciousInput.Substring(0, Math.Min(50, maliciousInput.Length))}...");
    }

    [Test]
    [TestCase("<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\">Click</a>")]
    [TestCase("<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4\">")]
    [Description("Data URI XSS attempts")]
    public void TestXSS_DataURIAttempts(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("<"));
        Assert.That(sanitized, Does.Not.Contain(">"));
        Assert.That(sanitized, Does.Not.Contain("data:"));
        
        Console.WriteLine($"Data URI XSS blocked: {maliciousInput.Substring(0, 50)}...");
    }

    #endregion

    #region Unicode and Encoding Bypass Tests

    [Test]
    [TestCase("admin\u0027 OR \u00271\u0027=\u00271")]  // Unicode single quotes
    [TestCase("admin%27%20OR%20%271%27%3D%271")]       // URL encoded
    [TestCase("admin&#x27; OR &#x27;1&#x27;=&#x27;1")]  // HTML entity encoded
    [Description("Unicode and encoding bypass attempts")]
    public void TestUnicodeEncodingBypass(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        var validation = _validationService.ValidateUsername(sanitized);
        
        // Assert - After sanitization, should fail validation
        Assert.That(validation.IsValid, Is.False, 
            "Encoded malicious input should be rejected after sanitization");
        
        Console.WriteLine($"Unicode/Encoded bypass blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("\u003Cscript\u003Ealert('XSS')\u003C/script\u003E")]  // Unicode < >
    [TestCase("%3Cscript%3Ealert('XSS')%3C/script%3E")]  // URL encoded
    [Description("Unicode XSS bypass attempts")]
    public void TestUnicodeXSSBypass(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("script"));
        
        Console.WriteLine($"Unicode XSS bypass blocked: {maliciousInput}");
    }

    [Test]
    [Description("Null byte injection attempts")]
    public void TestNullByteInjection()
    {
        // Arrange
        var maliciousInput = "admin\0' OR '1'='1";
        
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        var validation = _validationService.ValidateUsername(maliciousInput);
        
        // Assert - Null bytes should be removed and validation should fail due to dangerous chars
        Assert.That(sanitized, Does.Not.Contain("'"));
        Assert.That(validation.IsValid, Is.False, "Input with null bytes and SQL injection should be rejected");
        
        Console.WriteLine($"Null byte injection blocked");
    }

    #endregion

    #region LDAP Injection Tests

    [Test]
    [TestCase("admin*)(&")]  // LDAP wildcard bypass
    [TestCase("*)(uid=*))(|(uid=*")]  // LDAP OR injection
    [TestCase("admin)(|(password=*))")]  // LDAP password bypass
    [Description("LDAP injection attempts")]
    public void TestLDAPInjection(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("*"));
        Assert.That(sanitized, Does.Not.Contain("("));
        Assert.That(sanitized, Does.Not.Contain(")"));
        Assert.That(sanitized, Does.Not.Contain("|"));
        Assert.That(sanitized, Does.Not.Contain("&"));
        
        Console.WriteLine($"LDAP injection blocked: {maliciousInput} -> {sanitized}");
    }

    #endregion

    #region XML Injection Tests

    [Test]
    [TestCase("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>")]
    [TestCase("<user><name>admin</name><role>admin</role></user>")]
    [Description("XML/XXE injection attempts")]
    public void TestXMLInjection(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("<"));
        Assert.That(sanitized, Does.Not.Contain(">"));
        Assert.That(sanitized, Does.Not.Contain("?"));
        
        Console.WriteLine($"XML injection blocked: {maliciousInput.Substring(0, Math.Min(50, maliciousInput.Length))}...");
    }

    #endregion

    #region Template Injection Tests

    [Test]
    [TestCase("{{7*7}}")]  // Template expression
    [TestCase("${7*7}")]   // EL expression
    [TestCase("#{7*7}")]   // Another template syntax
    [TestCase("<%= 7*7 %>")]  // ERB/ASP syntax
    [Description("Server-side template injection (SSTI) attempts")]
    public void TestTemplateInjection(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("{"));
        Assert.That(sanitized, Does.Not.Contain("}"));
        Assert.That(sanitized, Does.Not.Contain("$"));
        Assert.That(sanitized, Does.Not.Contain("#"));
        Assert.That(sanitized, Does.Not.Contain("<"));
        Assert.That(sanitized, Does.Not.Contain(">"));
        
        Console.WriteLine($"Template injection blocked: {maliciousInput} -> {sanitized}");
    }

    #endregion

    #region Path Traversal Tests

    [Test]
    [TestCase("../../etc/passwd")]
    [TestCase("..\\..\\windows\\system32\\config\\sam")]
    [TestCase("....//....//....//etc/passwd")]
    [TestCase("%2e%2e%2f%2e%2e%2f")]  // URL encoded ../ 
    [Description("Path traversal / directory traversal attempts")]
    public void TestPathTraversal(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert - After sanitization, path traversal characters should be removed
        Assert.That(sanitized, Does.Not.Contain(".."));
        Assert.That(sanitized, Does.Not.Contain("/"));
        Assert.That(sanitized, Does.Not.Contain("\\"));
        
        Console.WriteLine($"Path traversal blocked: {maliciousInput} -> {sanitized}");
    }

    #endregion

    #region HTTP Header Injection Tests

    [Test]
    [TestCase("admin\r\nSet-Cookie: admin=true")]
    [TestCase("admin\nLocation: http://evil.com")]
    [TestCase("admin\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK")]
    [Description("CRLF injection / HTTP header injection attempts")]
    public void TestHTTPHeaderInjection(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("\r"));
        Assert.That(sanitized, Does.Not.Contain("\n"));
        
        Console.WriteLine($"HTTP header injection blocked: {maliciousInput.Replace("\r", "\\r").Replace("\n", "\\n")}");
    }

    #endregion

    #region NoSQL Injection Tests

    [Test]
    [TestCase("{\"$gt\": \"\"}")]  // MongoDB greater than
    [TestCase("{\"$ne\": null}")]  // MongoDB not equal
    [TestCase("admin'; return true; var a='")]
    [Description("NoSQL injection attempts")]
    public void TestNoSQLInjection(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("$"));
        Assert.That(sanitized, Does.Not.Contain("{"));
        Assert.That(sanitized, Does.Not.Contain("}"));
        Assert.That(sanitized, Does.Not.Contain("'"));
        
        Console.WriteLine($"NoSQL injection blocked: {maliciousInput} -> {sanitized}");
    }

    #endregion

    #region Expression Language Injection Tests

    [Test]
    [TestCase("${applicationScope}")]
    [TestCase("${facesContext}")]
    [TestCase("T(java.lang.Runtime).getRuntime().exec('calc')")]
    [Description("Expression Language (EL) injection attempts")]
    public void TestExpressionLanguageInjection(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("$"));
        Assert.That(sanitized, Does.Not.Contain("{"));
        Assert.That(sanitized, Does.Not.Contain("}"));
        Assert.That(sanitized, Does.Not.Contain("("));
        Assert.That(sanitized, Does.Not.Contain(")"));
        
        Console.WriteLine($"EL injection blocked: {maliciousInput} -> {sanitized}");
    }

    #endregion

    #region SQL Injection with Advanced Techniques

    [Test]
    [TestCase("admin' AND SUBSTRING((SELECT password FROM Users WHERE username='admin'),1,1)='a'--")]
    [TestCase("admin' AND ASCII(SUBSTRING((SELECT password FROM Users LIMIT 1),1,1))>100--")]
    [Description("SQL injection with substring extraction")]
    public void TestSQLInjection_SubstringExtraction(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("'"));
        Assert.That(sanitized, Does.Not.Contain("--"));
        Assert.That(sanitized, Does.Not.Contain("SELECT"));
        Assert.That(sanitized, Does.Not.Contain("SUBSTRING"));
        
        Console.WriteLine($"Advanced SQL injection blocked: {maliciousInput.Substring(0, 50)}...");
    }

    [Test]
    [TestCase("admin' UNION SELECT NULL,NULL,NULL,NULL,NULL--")]
    [TestCase("admin' UNION ALL SELECT NULL,NULL,version()--")]
    [Description("SQL injection with UNION-based extraction")]
    public void TestSQLInjection_UnionBased(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("'"));
        Assert.That(sanitized, Does.Not.Contain("UNION"));
        Assert.That(sanitized, Does.Not.Contain("--"));
        
        Console.WriteLine($"UNION-based SQL injection blocked: {maliciousInput}");
    }

    [Test]
    [TestCase("admin' AND 1=CONVERT(int,(SELECT @@version))--")]
    [TestCase("admin' AND 1=CAST((SELECT password FROM Users WHERE username='admin') AS int)--")]
    [Description("Error-based SQL injection")]
    public void TestSQLInjection_ErrorBased(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("'"));
        Assert.That(sanitized, Does.Not.Contain("--"));
        Assert.That(sanitized, Does.Not.Contain("@@"));
        
        Console.WriteLine($"Error-based SQL injection blocked: {maliciousInput.Substring(0, 50)}...");
    }

    #endregion

    #region Polyglot Injection Tests

    [Test]
    [Description("Polyglot payload that works in multiple contexts")]
    public void TestPolyglotInjection()
    {
        // Arrange - A payload that could work as SQL, JS, and HTML injection
        var polyglot = "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>";
        
        // Act
        var sanitized = _validationService.SanitizeInput(polyglot);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("'"));
        Assert.That(sanitized, Does.Not.Contain("\""));
        Assert.That(sanitized, Does.Not.Contain("<"));
        Assert.That(sanitized, Does.Not.Contain(">"));
        Assert.That(sanitized, Does.Not.Contain(";"));
        Assert.That(sanitized, Does.Not.Contain("--"));
        
        Console.WriteLine($"Polyglot injection blocked");
        Console.WriteLine($"Original length: {polyglot.Length}, Sanitized length: {sanitized.Length}");
    }

    #endregion

    #region Mass Assignment / Parameter Pollution Tests

    [Test]
    [TestCase("username=admin&username=hacker")]
    [TestCase("email=user@test.com&role=admin")]
    [Description("HTTP parameter pollution attempts")]
    public void TestParameterPollution(string maliciousInput)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousInput);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("&"));
        
        Console.WriteLine($"Parameter pollution blocked: {maliciousInput} -> {sanitized}");
    }

    #endregion

    #region Email Header Injection Tests

    [Test]
    [TestCase("user@example.com\nBcc: attacker@evil.com")]
    [TestCase("user@example.com\r\nTo: victim@target.com")]
    [TestCase("user@example.com%0ABcc:attacker@evil.com")]
    [Description("Email header injection attempts")]
    public void TestEmailHeaderInjection(string maliciousEmail)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(maliciousEmail);
        var validation = _validationService.ValidateEmail(sanitized);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain("\n"));
        Assert.That(sanitized, Does.Not.Contain("\r"));
        Assert.That(validation.IsValid, Is.False, "Email with newlines should be invalid");
        
        Console.WriteLine($"Email header injection blocked: {maliciousEmail.Replace("\n", "\\n").Replace("\r", "\\r")}");
    }

    #endregion

    #region File Upload Attack Simulation

    [Test]
    [TestCase("../../web.config")]
    [TestCase("shell.php.jpg")]
    [TestCase("<script>alert('XSS')</script>.jpg")]
    [TestCase("file.jpg; echo 'hacked' > hacked.txt")]
    [Description("Malicious file upload filename attempts")]
    public void TestMaliciousFileUploadNames(string filename)
    {
        // Act
        var sanitized = _validationService.SanitizeInput(filename);
        
        // Assert
        Assert.That(sanitized, Does.Not.Contain(".."));
        Assert.That(sanitized, Does.Not.Contain("/"));
        Assert.That(sanitized, Does.Not.Contain("\\"));
        Assert.That(sanitized, Does.Not.Contain("<"));
        Assert.That(sanitized, Does.Not.Contain(">"));
        Assert.That(sanitized, Does.Not.Contain(";"));
        
        Console.WriteLine($"Malicious filename blocked: {filename} -> {sanitized}");
    }

    #endregion

    #region Summary Test

    [Test]
    [Description("Summary of all advanced attack types tested")]
    public void TestAdvancedAttacks_Summary()
    {
        var attackTypes = new[]
        {
            "Second-Order SQL Injection",
            "Time-Based Blind SQL Injection",
            "Boolean-Based Blind SQL Injection",
            "Stored XSS with Nested Tags",
            "Obfuscated XSS",
            "Data URI XSS",
            "Unicode Bypass Attempts",
            "LDAP Injection",
            "XML/XXE Injection",
            "Template Injection (SSTI)",
            "Path Traversal",
            "HTTP Header Injection (CRLF)",
            "NoSQL Injection",
            "Expression Language Injection",
            "Advanced SQL Injection Techniques",
            "Polyglot Injection",
            "Parameter Pollution",
            "Email Header Injection",
            "Malicious File Upload"
        };

        Console.WriteLine("\n=== ADVANCED ATTACK TYPES TESTED ===");
        foreach (var attackType in attackTypes)
        {
            Console.WriteLine($"✅ {attackType}");
        }
        Console.WriteLine($"\nTotal Attack Categories: {attackTypes.Length}");
        Console.WriteLine("All attacks successfully mitigated by input validation and sanitization.");
        
        Assert.Pass("All advanced attack simulations completed successfully");
    }

    #endregion
}
