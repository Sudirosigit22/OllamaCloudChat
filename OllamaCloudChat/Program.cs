using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using OllamaSharp;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizeFolder("/");
    options.Conventions.AllowAnonymousToPage("/Login");
});

builder.Services.AddHttpClient("default", client =>
{
    client.BaseAddress = new Uri("http://localhost:11434/");
    client.Timeout = TimeSpan.FromMinutes(5);
});

builder.Services.AddScoped<OllamaApiClient>(_ =>
{
    return new OllamaApiClient("http://localhost:11434");
});

var key = "MY_SUPER_LONG_SECRET_KEY_FOR_JWT_TOKEN_SECURITY_2026_CHATBOT_APP";
var keyBytes = Encoding.UTF8.GetBytes(key);

builder.Services
.AddAuthentication(options =>
{

    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.LoginPath = "/Login";
    options.AccessDeniedPath = "/Login";
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters = new()
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes)
    };
});


builder.Services.AddAuthorization();

builder.Services.AddRateLimiter(opt =>
{
    opt.AddFixedWindowLimiter("chat-limit", o =>
    {
        o.PermitLimit = 10;
        o.Window = TimeSpan.FromMinutes(1);
        o.QueueLimit = 2;
        o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });
});

var app = builder.Build();

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();


app.MapPost("/login", (UserLogin login) =>
{
    if (login.Username == "admin" && login.Password == "123")
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, login.Username)
        };

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddHours(2),
            signingCredentials:
                new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                    SecurityAlgorithms.HmacSha256)
        );

        return Results.Ok(new
        {
            token = new JwtSecurityTokenHandler().WriteToken(token)
        });
    }

    return Results.Unauthorized();
});


app.MapPost("/chat", async (OllamaApiClient ollama, ChatDto dto) =>
{
    if (string.IsNullOrEmpty(dto.Message)) return Results.BadRequest();

    ollama.SelectedModel = "gpt-oss:120b-cloud";

    var sb = new StringBuilder();
    await foreach (var chunk in ollama.GenerateAsync(dto.Message))
    {
        sb.Append(chunk?.Response);
    }
    return Results.Ok(new { answer = sb.ToString() });
})
.RequireAuthorization(new AuthorizeAttribute
{
    AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme
})
.RequireRateLimiting("chat-limit");

app.MapGet("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

    ctx.Response.Cookies.Delete("jwt");

    return Results.Redirect("/Login");
});




app.MapRazorPages();

app.Run();

record UserLogin(string Username, string Password);
record ChatDto(string Message);
