using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using OauthApi.JWT;
using OauthApi.Options;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add authentication services
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "Bearer";
    options.DefaultChallengeScheme = "Bearer";
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "OauthAPI",
        ValidAudience = "Swagger",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("f7c2b6a24e124f2d81e03d7f11d01c6b"))
    };
})
.AddOAuth("GitHub", options =>
{
    options.ClientId = builder.Configuration["GitHubAuth:ClientId"];
    options.ClientSecret = builder.Configuration["GitHubAuth:ClientSecret"];
    options.CallbackPath = new PathString("/api/github/github-callback");
    options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
    options.TokenEndpoint = "https://github.com/login/oauth/access_token";
    options.Scope.Add("user");
    options.SaveTokens = true;
    options.ClaimActions.MapJsonKey("urn:github:login", "login");
})
.AddOAuth("Google", options =>
{
    options.ClientId = builder.Configuration["GoogleAuth:ClientId"];
    options.ClientSecret = builder.Configuration["GoogleAuth:ClientSecret"];
    options.CallbackPath = new PathString("/api/auth/callback/google");
    options.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    options.TokenEndpoint = "https://oauth2.googleapis.com/token";
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.SaveTokens = true;
    options.ClaimActions.MapJsonKey("urn:google:name", "name");
})
.AddOAuth("Facebook", options =>
{
    options.ClientId = builder.Configuration["FacebookAuth:ClientId"];
    options.ClientSecret = builder.Configuration["FacebookAuth:ClientSecret"];
    options.CallbackPath = new PathString("/api/auth/callback/facebook");
    options.AuthorizationEndpoint = "https://www.facebook.com/v13.0/dialog/oauth";
    options.TokenEndpoint = "https://graph.facebook.com/v13.0/oauth/access_token";
    options.Scope.Add("email");
    options.SaveTokens = true;
    options.ClaimActions.MapJsonKey("urn:facebook:name", "name");
});

// Register configuration classes
builder.Services.Configure<GitHubOptions>(builder.Configuration.GetSection("GitHubAuth"));
builder.Services.Configure<GoogleOptions>(builder.Configuration.GetSection("GoogleAuth"));
builder.Services.Configure<FacebookOptions>(builder.Configuration.GetSection("FacebookAuth"));

// Add HTTP client factory for external API calls
builder.Services.AddHttpClient();

// Add services for JWT token generation
builder.Services.AddSingleton<IJwtService, JwtService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Enable authentication middleware
app.UseAuthentication();

// Enable authorization middleware
app.UseAuthorization();

app.MapControllers();

app.Run();
