using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OauthApi.JWT;

namespace OauthApi.Controllers;
[Route("api/[controller]")]
[ApiController]
public class GitHubController : ControllerBase
{
    private readonly IJwtService _jwtService;

    public GitHubController (IJwtService jwtService)
    {
        _jwtService = jwtService;
    }

    [HttpGet("login/github")]
    public IActionResult LoginGitHub ()
    {
        var authProperty = new AuthenticationProperties
        {
            RedirectUri = "/api/github/github-callback"
        };

        return Challenge(authProperty, "GitHub");
    }

    [HttpGet("github-callback")]
    public async Task<IActionResult> Callback ()
    {
        var authResult = await HttpContext.AuthenticateAsync();

        if (!authResult.Succeeded || authResult.Principal == null)
        {
            return BadRequest(new { Error = "Auth failed" });
        }

        var userName = authResult.Principal.FindFirst("urn:github:login")?.Value;

        if (string.IsNullOrEmpty(userName))
        {
            return BadRequest(new { Error = "User not found" });
        }

        var jwtToken = _jwtService.GenerateToken(userName);

        return Ok(new { Token = jwtToken });
    }
}
