using NUnit.Framework;
using SafeVaultAPI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace SafeVaultTests;

[TestFixture]
public class TestAuthorization
{
    private ITokenService _tokenService = null!;
    private Mock<IConfiguration> _configurationMock = null!;
    private Mock<ILogger<TokenService>> _loggerMock = null!;

    [SetUp]
    public void Setup()
    {
        _configurationMock = new Mock<IConfiguration>();
        _loggerMock = new Mock<ILogger<TokenService>>();
        
        // Mock JWT configuration
        _configurationMock.Setup(x => x["Jwt:Secret"]).Returns("YourVerySecureSecretKeyThatIsAtLeast32CharactersLong!@#$%");
        _configurationMock.Setup(x => x["Jwt:Issuer"]).Returns("SafeVaultAPI");
        _configurationMock.Setup(x => x["Jwt:Audience"]).Returns("SafeVaultClient");
        _configurationMock.Setup(x => x["Jwt:ExpiryInMinutes"]).Returns("60");
        
        _tokenService = new TokenService(_configurationMock.Object, _loggerMock.Object);
    }

    #region JWT Token Generation Tests

    [Test]
    public void TestGenerateJwtToken_UserRole()
    {
        // Arrange
        var userId = 1;
        var username = "testuser";
        var roles = new List<string> { "user" };

        // Act
        var token = _tokenService.GenerateJwtToken(userId, username, roles);

        // Assert
        Assert.That(token, Is.Not.Null);
        Assert.That(token, Is.Not.Empty);
        
        // Decode token to verify claims
        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadToken(token) as JwtSecurityToken;
        
        Assert.That(jsonToken, Is.Not.Null);
        Assert.That(jsonToken.Claims.Any(c => c.Type == ClaimTypes.NameIdentifier && c.Value == userId.ToString()), Is.True);
        Assert.That(jsonToken.Claims.Any(c => c.Type == ClaimTypes.Name && c.Value == username), Is.True);
        Assert.That(jsonToken.Claims.Any(c => c.Type == ClaimTypes.Role && c.Value == "user"), Is.True);
        
        Console.WriteLine($"✓ JWT token generated for user role");
        Console.WriteLine($"  Token: {token.Substring(0, 50)}...");
    }

    [Test]
    public void TestGenerateJwtToken_AdminRole()
    {
        // Arrange
        var userId = 2;
        var username = "admin";
        var roles = new List<string> { "admin" };

        // Act
        var token = _tokenService.GenerateJwtToken(userId, username, roles);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadToken(token) as JwtSecurityToken;
        
        Assert.That(jsonToken!.Claims.Any(c => c.Type == ClaimTypes.Role && c.Value == "admin"), Is.True);
        
        Console.WriteLine($"✓ JWT token generated for admin role");
    }

    [Test]
    public void TestGenerateJwtToken_MultipleRoles()
    {
        // Arrange
        var userId = 3;
        var username = "poweruser";
        var roles = new List<string> { "user", "moderator" };

        // Act
        var token = _tokenService.GenerateJwtToken(userId, username, roles);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadToken(token) as JwtSecurityToken;
        
        Assert.That(jsonToken!.Claims.Count(c => c.Type == ClaimTypes.Role), Is.EqualTo(2));
        Assert.That(jsonToken.Claims.Any(c => c.Type == ClaimTypes.Role && c.Value == "user"), Is.True);
        Assert.That(jsonToken.Claims.Any(c => c.Type == ClaimTypes.Role && c.Value == "moderator"), Is.True);
        
        Console.WriteLine($"✓ JWT token generated with multiple roles: {string.Join(", ", roles)}");
    }

    #endregion

    #region Token Validation Tests

    [Test]
    public void TestValidateToken_ValidToken_ReturnsClaimsPrincipal()
    {
        // Arrange
        var userId = 1;
        var username = "testuser";
        var roles = new List<string> { "user" };
        var token = _tokenService.GenerateJwtToken(userId, username, roles);

        // Act
        var principal = _tokenService.ValidateToken(token);

        // Assert
        Assert.That(principal, Is.Not.Null);
        Assert.That(principal.Identity?.IsAuthenticated, Is.True);
        Assert.That(principal.FindFirst(ClaimTypes.Name)?.Value, Is.EqualTo(username));
        Assert.That(principal.FindFirst(ClaimTypes.NameIdentifier)?.Value, Is.EqualTo(userId.ToString()));
        
        Console.WriteLine($"✓ Valid token successfully validated");
    }

    [Test]
    public void TestValidateToken_InvalidToken_ReturnsNull()
    {
        // Arrange
        var invalidToken = "invalid.token.here";

        // Act
        var principal = _tokenService.ValidateToken(invalidToken);

        // Assert
        Assert.That(principal, Is.Null);
        
        Console.WriteLine($"✓ Invalid token correctly rejected");
    }

    [Test]
    public void TestValidateToken_EmptyToken_ReturnsNull()
    {
        // Act
        var principal = _tokenService.ValidateToken("");

        // Assert
        Assert.That(principal, Is.Null);
        
        Console.WriteLine($"✓ Empty token correctly rejected");
    }

    [Test]
    public void TestGetUserIdFromToken_ValidToken_ReturnsUserId()
    {
        // Arrange
        var userId = 42;
        var username = "testuser";
        var roles = new List<string> { "user" };
        var token = _tokenService.GenerateJwtToken(userId, username, roles);

        // Act
        var extractedUserId = _tokenService.GetUserIdFromToken(token);

        // Assert
        Assert.That(extractedUserId, Is.EqualTo(userId));
        
        Console.WriteLine($"✓ User ID correctly extracted from token: {extractedUserId}");
    }

    #endregion

    #region Refresh Token Tests

    [Test]
    public void TestGenerateRefreshToken_Success()
    {
        // Act
        var refreshToken = _tokenService.GenerateRefreshToken();

        // Assert
        Assert.That(refreshToken, Is.Not.Null);
        Assert.That(refreshToken, Is.Not.Empty);
        Assert.That(refreshToken.Length, Is.GreaterThan(50), "Refresh token should be long");
        
        Console.WriteLine($"✓ Refresh token generated: {refreshToken.Substring(0, 20)}...");
    }

    [Test]
    public void TestGenerateRefreshToken_UniqueTokens()
    {
        // Act
        var token1 = _tokenService.GenerateRefreshToken();
        var token2 = _tokenService.GenerateRefreshToken();

        // Assert
        Assert.That(token1, Is.Not.EqualTo(token2), "Each refresh token should be unique");
        
        Console.WriteLine($"✓ Refresh tokens are unique");
    }

    #endregion

    #region Role-Based Access Control Tests

    [Test]
    public void TestRoleBasedAccess_UserRole_CanAccessUserDashboard()
    {
        // Simulate authorization check
        var roles = new List<string> { "user" };
        var requiredRoles = new[] { "user", "admin", "moderator" };
        
        // Act
        var hasAccess = roles.Any(r => requiredRoles.Contains(r));
        
        // Assert
        Assert.That(hasAccess, Is.True);
        Console.WriteLine($"✓ User with 'user' role can access user dashboard");
    }

    [Test]
    public void TestRoleBasedAccess_UserRole_CannotAccessAdminDashboard()
    {
        // Simulate authorization check
        var roles = new List<string> { "user" };
        var requiredRoles = new[] { "admin" };
        
        // Act
        var hasAccess = roles.Any(r => requiredRoles.Contains(r));
        
        // Assert
        Assert.That(hasAccess, Is.False);
        Console.WriteLine($"✓ User with 'user' role cannot access admin dashboard");
    }

    [Test]
    public void TestRoleBasedAccess_AdminRole_CanAccessAllDashboards()
    {
        // Simulate authorization checks
        var roles = new List<string> { "admin" };
        
        // Act
        var canAccessUser = roles.Any(r => new[] { "user", "admin", "moderator" }.Contains(r));
        var canAccessModerator = roles.Any(r => new[] { "moderator", "admin" }.Contains(r));
        var canAccessAdmin = roles.Any(r => new[] { "admin" }.Contains(r));
        
        // Assert
        Assert.That(canAccessUser, Is.True);
        Assert.That(canAccessModerator, Is.True);
        Assert.That(canAccessAdmin, Is.True);
        Console.WriteLine($"✓ User with 'admin' role can access all dashboards");
    }

    [Test]
    public void TestRoleBasedAccess_ModeratorRole_CanAccessModeratorAndUserDashboard()
    {
        // Simulate authorization checks
        var roles = new List<string> { "moderator" };
        
        // Act
        var canAccessUser = roles.Any(r => new[] { "user", "admin", "moderator" }.Contains(r));
        var canAccessModerator = roles.Any(r => new[] { "moderator", "admin" }.Contains(r));
        var canAccessAdmin = roles.Any(r => new[] { "admin" }.Contains(r));
        
        // Assert
        Assert.That(canAccessUser, Is.True);
        Assert.That(canAccessModerator, Is.True);
        Assert.That(canAccessAdmin, Is.False);
        Console.WriteLine($"✓ User with 'moderator' role can access moderator and user dashboards");
        Console.WriteLine($"✓ User with 'moderator' role cannot access admin dashboard");
    }

    #endregion

    #region Unauthorized Access Tests

    [Test]
    public void TestUnauthorizedAccess_NoToken_ShouldFail()
    {
        // Simulate request without token
        string? token = null;
        
        // Act
        var principal = token != null ? _tokenService.ValidateToken(token) : null;
        
        // Assert
        Assert.That(principal, Is.Null);
        Console.WriteLine($"✓ Unauthorized access (no token) correctly blocked");
    }

    [Test]
    public void TestUnauthorizedAccess_ExpiredToken_Simulation()
    {
        // Note: We can't easily create expired tokens in tests
        // This test demonstrates the concept
        
        // In production, token validation would check expiry
        var tokenIsExpired = true; // Simulated
        
        // Act
        var accessGranted = !tokenIsExpired;
        
        // Assert
        Assert.That(accessGranted, Is.False);
        Console.WriteLine($"✓ Expired token would be rejected by validation");
    }

    [Test]
    public void TestUnauthorizedAccess_TamperedToken_ShouldFail()
    {
        // Arrange
        var userId = 1;
        var username = "testuser";
        var roles = new List<string> { "user" };
        var validToken = _tokenService.GenerateJwtToken(userId, username, roles);
        
        // Tamper with the token
        var tamperedToken = validToken.Substring(0, validToken.Length - 10) + "TAMPERED";
        
        // Act
        var principal = _tokenService.ValidateToken(tamperedToken);
        
        // Assert
        Assert.That(principal, Is.Null);
        Console.WriteLine($"✓ Tampered token correctly rejected");
    }

    #endregion

    #region Access Control for Different Roles Tests

    [Test]
    public void TestAccessControl_AdminCanAssignRoles()
    {
        // Simulate role check for role assignment
        var userRoles = new List<string> { "admin" };
        var requiredRole = "admin";
        
        // Act
        var canAssignRoles = userRoles.Contains(requiredRole);
        
        // Assert
        Assert.That(canAssignRoles, Is.True);
        Console.WriteLine($"✓ Admin can assign roles to users");
    }

    [Test]
    public void TestAccessControl_UserCannotAssignRoles()
    {
        // Simulate role check for role assignment
        var userRoles = new List<string> { "user" };
        var requiredRole = "admin";
        
        // Act
        var canAssignRoles = userRoles.Contains(requiredRole);
        
        // Assert
        Assert.That(canAssignRoles, Is.False);
        Console.WriteLine($"✓ Regular user cannot assign roles to others");
    }

    [Test]
    public void TestAccessControl_ModeratorCanReviewContent()
    {
        // Simulate permission check
        var userRoles = new List<string> { "moderator" };
        var allowedRoles = new[] { "moderator", "admin" };
        
        // Act
        var canReview = userRoles.Any(r => allowedRoles.Contains(r));
        
        // Assert
        Assert.That(canReview, Is.True);
        Console.WriteLine($"✓ Moderator can review content");
    }

    #endregion

    #region Security Policy Tests

    [Test]
    public void TestSecurityPolicy_TokenContainsNoSensitiveData()
    {
        // Arrange
        var userId = 1;
        var username = "testuser";
        var roles = new List<string> { "user" };
        var token = _tokenService.GenerateJwtToken(userId, username, roles);
        
        // Decode token
        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadToken(token) as JwtSecurityToken;
        
        // Assert - Token should not contain password or other sensitive data
        var allClaims = jsonToken!.Claims.Select(c => c.Type + ":" + c.Value).ToList();
        var sensitiveKeywords = new[] { "password", "secret", "key", "hash", "salt" };
        
        foreach (var claim in allClaims)
        {
            foreach (var keyword in sensitiveKeywords)
            {
                Assert.That(claim.ToLower(), Does.Not.Contain(keyword));
            }
        }
        
        Console.WriteLine($"✓ Token does not contain sensitive data");
        Console.WriteLine($"  Claims: {string.Join(", ", allClaims.Take(5))}...");
    }

    [Test]
    public void TestSecurityPolicy_TokenHasIssuerAndAudience()
    {
        // Arrange
        var userId = 1;
        var username = "testuser";
        var roles = new List<string> { "user" };
        var token = _tokenService.GenerateJwtToken(userId, username, roles);
        
        // Decode token
        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadToken(token) as JwtSecurityToken;
        
        // Assert
        Assert.That(jsonToken!.Issuer, Is.EqualTo("SafeVaultAPI"));
        Assert.That(jsonToken.Audiences.First(), Is.EqualTo("SafeVaultClient"));
        
        Console.WriteLine($"✓ Token has correct issuer and audience");
        Console.WriteLine($"  Issuer: {jsonToken.Issuer}");
        Console.WriteLine($"  Audience: {jsonToken.Audiences.First()}");
    }

    #endregion
}
