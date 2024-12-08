namespace OauthApi.JWT;

public interface IJwtService
{
    string GenerateToken (string username);
}
