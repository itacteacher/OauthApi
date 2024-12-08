using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OauthApi.JWT;
using OauthApi.Options;
using System.Text.Json;

namespace OauthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IJwtService _jwtService;

        private readonly GitHubOptions _gitHubAuthOptions;
        private readonly GoogleOptions _googleAuthOptions;
        private readonly FacebookOptions _facebookAuthOptions;

        public AuthController (IHttpClientFactory httpClientFactory,
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

        [HttpGet("login/github")]
        public IActionResult LoginGitHub ()
        {
            var url = $"https://github.com/login/oauth/authorize?client_id={_gitHubAuthOptions.ClientId}&redirect_uri={_gitHubAuthOptions.RedirectUri}&scope=user";
            return Redirect(url);
        }

        [HttpGet("login/google")]
        public IActionResult LoginGoogle ()
        {
            var url = $"https://accounts.google.com/o/oauth2/v2/auth?client_id={_googleAuthOptions.ClientId}&redirect_uri={_googleAuthOptions.RedirectUri}&response_type=code&scope=openid%20profile%20email";
            return Redirect(url);
        }

        [HttpGet("login/facebook")]
        public IActionResult LoginFacebook ()
        {
            var url = $"https://www.facebook.com/v13.0/dialog/oauth?client_id={_facebookAuthOptions.ClientId}&redirect_uri={_facebookAuthOptions.RedirectUri}&scope=email";
            return Redirect(url);
        }

        [HttpGet("callback/github")]
        public async Task<IActionResult> CallbackGitHub ([FromQuery] string code)
        {
            if (string.IsNullOrEmpty(code))
            {
                return BadRequest(new { Error = "Missing code in query" });
            }

            try
            {
                var client = _httpClientFactory.CreateClient();

                var formedContent = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "client_id", _gitHubAuthOptions.ClientId },
                    { "client_secret", _gitHubAuthOptions.ClientSecret },
                    { "code", code },
                    { "redirect_uri", _gitHubAuthOptions.RedirectUri }
                });

                var tokenResponse = await client.PostAsync("https://github.com/login/oauth/access_token", formedContent);

                tokenResponse.EnsureSuccessStatusCode();

                var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
                var accessToken = System.Web.HttpUtility.ParseQueryString(tokenContent)["access_token"];

                if (string.IsNullOrEmpty(accessToken))
                {
                    return BadRequest(new { Error = "Failed to retrieve access token" });
                }

                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                client.DefaultRequestHeaders.UserAgent.ParseAdd("OauthAPI");

                var userResponse = await client.GetAsync("https://api.github.com/user");
                userResponse.EnsureSuccessStatusCode();

                var userContent = await userResponse.Content.ReadAsStringAsync();
                var userName = JsonDocument.Parse(userContent).RootElement.GetProperty("login").GetString();

                var jwtToken = _jwtService.GenerateToken(userName);

                return Ok(new { Token = jwtToken });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet("callback/google")]
        public async Task<IActionResult> CallbackGoogle ([FromQuery] string code)
        {
            if (string.IsNullOrEmpty(code))
            {
                return BadRequest(new { Error = "Missing code in query" });
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                var formedContent = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "code", code },
                    { "client_id", _googleAuthOptions.ClientId },
                    { "client_secret", _googleAuthOptions.ClientSecret },
                    { "redirect_uri", _googleAuthOptions.RedirectUri },
                    { "grant_type", "authorization_code" }
                });

                var tokenResponse = await client.PostAsync("https://oauth2.googleapis.com/token", formedContent);
                tokenResponse.EnsureSuccessStatusCode();

                var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
                var accessToken = JsonDocument.Parse(tokenContent).RootElement.GetProperty("access_token").GetString();

                if (string.IsNullOrEmpty(accessToken))
                {
                    return BadRequest(new { Error = "Failed to retrieve access token" });
                }

                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                var userResponse = await client.GetAsync("https://www.googleapis.com/oauth2/v1/userinfo?alt=json");
                userResponse.EnsureSuccessStatusCode();

                var userContent = await userResponse.Content.ReadAsStringAsync();
                var userName = JsonDocument.Parse(userContent).RootElement.GetProperty("name").GetString();

                var jwtToken = _jwtService.GenerateToken(userName);

                return Ok(new { Token = jwtToken });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet("callback/facebook")]
        public async Task<IActionResult> CallbackFacebook ([FromQuery] string code)
        {
            if (string.IsNullOrEmpty(code))
            {
                return BadRequest(new { Error = "Missing code in query" });
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                var tokenUrl = $"https://graph.facebook.com/v13.0/oauth/access_token?client_id={_facebookAuthOptions.ClientId}&redirect_uri={_facebookAuthOptions.RedirectUri}&client_secret={_facebookAuthOptions.ClientSecret}&code={code}";

                var tokenResponse = await client.GetAsync(tokenUrl);
                tokenResponse.EnsureSuccessStatusCode();

                var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
                var accessToken = JsonDocument.Parse(tokenContent).RootElement.GetProperty("access_token").GetString();

                if (string.IsNullOrEmpty(accessToken))
                {
                    return BadRequest(new { Error = "Failed to retrieve access token" });
                }

                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
                var userResponse = await client.GetAsync("https://graph.facebook.com/me?fields=id,name,email");
                userResponse.EnsureSuccessStatusCode();

                var userContent = await userResponse.Content.ReadAsStringAsync();
                var userName = JsonDocument.Parse(userContent).RootElement.GetProperty("name").GetString();

                var jwtToken = _jwtService.GenerateToken(userName);

                return Ok(new { Token = jwtToken });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
