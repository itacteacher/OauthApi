using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OauthApi.JWT;
using OauthApi.Options;
using System.Text.Json;

namespace OauthApi.Controllers;
[Route("api/[controller]")]
[ApiController]
public class Auth2Controller : ControllerBase
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IJwtService _jwtService;

    private readonly GitHubOptions _gitHubAuthOptions;
    private readonly GoogleOptions _googleAuthOptions;
    private readonly FacebookOptions _facebookAuthOptions;

    public Auth2Controller (IHttpClientFactory httpClientFactory,
        IJwtService jwtService,
        IOptions<GitHubOptions> gitHubAuthOptions,
        IOptions<GoogleOptions> googleAuthOptions,
        IOptions<FacebookOptions> facebookAuthOptions)
    {
        _httpClientFactory = httpClientFactory;
        _jwtService = jwtService;

        _gitHubAuthOptions = gitHubAuthOptions.Value;
        _googleAuthOptions = googleAuthOptions.Value;
        _facebookAuthOptions = facebookAuthOptions.Value;
    }

    [HttpGet("login/{provider}")]
    public IActionResult Login (string provider)
    {
        string url;

        switch (provider.ToLower())
        {
            case "github":
                url = $"https://github.com/login/oauth/authorize?client_id={_gitHubAuthOptions.ClientId}&redirect_uri={_gitHubAuthOptions.RedirectUri}&scope=user";
                break;

            case "google":
                url = $"https://accounts.google.com/o/oauth2/v2/auth?client_id={_googleAuthOptions.ClientId}&redirect_uri={_googleAuthOptions.RedirectUri}&response_type=code&scope=openid%20profile%20email";
                break;

            case "facebook":
                url = $"https://www.facebook.com/v13.0/dialog/oauth?client_id={_facebookAuthOptions.ClientId}&redirect_uri={_facebookAuthOptions.RedirectUri}&scope=email";
                break;

            default:
                return BadRequest(new { Error = "Unsupported provider" });
        }

        return Redirect(url);
    }

    [HttpGet("callback/{provider}")]
    public async Task<IActionResult> Callback (string code, string provider)
    {
        return await HandleOAuthCallback(code, provider);
    }

    private async Task<IActionResult> HandleOAuthCallback (string code, string provider)
    {
        if (string.IsNullOrEmpty(code))
        {
            return BadRequest(new { Error = "Missing code in query" });
        }

        try
        {
            var client = _httpClientFactory.CreateClient();
            string tokenUrl = string.Empty;
            string userInfoUrl = string.Empty;
            string clientId = string.Empty;
            string clientSecret = string.Empty;
            string redirectUri = string.Empty;

            switch (provider.ToLower())
            {
                case "github":
                    tokenUrl = "https://github.com/login/oauth/access_token";
                    userInfoUrl = "https://api.github.com/user";
                    clientId = _gitHubAuthOptions.ClientId;
                    clientSecret = _gitHubAuthOptions.ClientSecret;
                    redirectUri = _gitHubAuthOptions.RedirectUri;
                    break;

                case "google":
                    tokenUrl = "https://oauth2.googleapis.com/token";
                    userInfoUrl = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json";
                    clientId = _googleAuthOptions.ClientId;
                    clientSecret = _googleAuthOptions.ClientSecret;
                    redirectUri = _googleAuthOptions.RedirectUri;
                    break;

                case "facebook":
                    tokenUrl = "https://graph.facebook.com/v13.0/oauth/access_token";
                    userInfoUrl = "https://graph.facebook.com/me?fields=id,name,email";
                    clientId = _facebookAuthOptions.ClientId;
                    clientSecret = _facebookAuthOptions.ClientSecret;
                    redirectUri = _facebookAuthOptions.RedirectUri;
                    break;

                default:
                    return BadRequest(new { Error = "Unsupported provider" });
            }

            var formedContent = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "code", code },
                { "client_id", clientId },
                { "client_secret", clientSecret },
                { "redirect_uri", redirectUri }
            });

            var tokenResponse = await client.PostAsync(tokenUrl, formedContent);
            tokenResponse.EnsureSuccessStatusCode();

            var tokenContent = await tokenResponse.Content.ReadAsStringAsync();

            string accessToken = provider.ToLower() switch
            {
                "github" => System.Web.HttpUtility.ParseQueryString(tokenContent)["access_token"],
                "google" => JsonDocument.Parse(tokenContent).RootElement.GetProperty("access_token").GetString(),
                "facebook" => JsonDocument.Parse(tokenContent).RootElement.GetProperty("access_token").GetString(),
                _ => throw new InvalidOperationException("Unsupported provider")
            };

            if (string.IsNullOrEmpty(accessToken))
            {
                return BadRequest(new { Error = "" });
            }

            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            var userResponse = await client.GetAsync(userInfoUrl);
            userResponse.EnsureSuccessStatusCode();

            var userContent = await userResponse.Content.ReadAsStringAsync();
            string userName = provider.ToLower() switch
            {
                "github" => JsonDocument.Parse(userContent).RootElement.GetProperty("login").GetString(),
                "google" => JsonDocument.Parse(tokenContent).RootElement.GetProperty("name").GetString(),
                "facebook" => JsonDocument.Parse(tokenContent).RootElement.GetProperty("name").GetString(),
                _ => throw new InvalidOperationException("Unsupported provider")
            };

            var jwtToken = _jwtService.GenerateToken(userName!);

            return Ok(new { Token = jwtToken });
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }
}
