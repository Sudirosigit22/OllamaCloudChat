using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;

public class LoginModel : PageModel
{
    [BindProperty]
    public string? ErrorMessage { get; set; }

    public async Task<IActionResult> OnPostAsync(string Username, string Password)
    {
        if (Username != "admin" || Password != "123")
        {
            ErrorMessage = "Username atau password salah";
            return Page();
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, Username)
        };

        var identity = new ClaimsIdentity(
            claims,
            CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));

        var key = "MY_SUPER_LONG_SECRET_KEY_FOR_JWT_TOKEN_SECURITY_2026_CHATBOT_APP";

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddHours(2),
            signingCredentials:
                new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                    SecurityAlgorithms.HmacSha256)
        );

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);

        Response.Cookies.Append("jwt", jwt, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax
        });

        return Redirect("/");
    }
}
